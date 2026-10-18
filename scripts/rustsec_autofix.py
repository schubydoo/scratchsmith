#!/usr/bin/env python3
"""Lockfile-only fix for RustSec advisories, for rustsec-autofix.yml.

Usage: rustsec_autofix.py <out_dir>

For each workspace lockfile (Cargo.lock, fuzz/Cargo.lock) it runs `cargo audit`, then
`cargo update -p <crate>@<vulnerable version>` for every hit, then audits again. Renovate
cannot do this: its OSV alerts cover direct deps only, and a crate pinned only in a
lockfile waits for the weekly lockFileMaintenance.

`cargo update -p` stays inside the semver ranges that Cargo.toml allows, so it never
edits a manifest. An advisory whose fix needs a manifest change stays unfixed and is
reported, never forced.

Writes into <out_dir>: `body.md` (PR body) and `summary.json`
({"fixed": [...], "remaining": [...], "main_changed": bool}). If the main lockfile
changed, also writes `.changeset/<first advisory id>.md` in the repo. The name is per
advisory, so a later run never overwrites an unreleased fragment from an earlier one.
"""

import json
import pathlib
import subprocess
import sys
import tomllib
from typing import NoReturn

WORKSPACES = (pathlib.Path("."), pathlib.Path("fuzz"))
CHANGESETS = pathlib.Path(".changeset")


def die(msg: str) -> NoReturn:
    sys.exit(f"rustsec_autofix: {msg}")


def audit(ws: pathlib.Path) -> list[dict]:
    """The vulnerability list of one lockfile. Warnings (unmaintained, yanked) are ignored."""
    # cargo audit exits 1 when it finds something, so the exit code is no error signal.
    # A run that produced no JSON is one.
    proc = subprocess.run(
        ["cargo", "audit", "--json", "--file", str(ws / "Cargo.lock")],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        die(f"cargo audit on {ws / 'Cargo.lock'} gave no JSON:\n{proc.stderr}")
    return report["vulnerabilities"]["list"]


def locked_versions(ws: pathlib.Path, name: str) -> list[str]:
    lock = tomllib.loads((ws / "Cargo.lock").read_text())
    return sorted({p["version"] for p in lock.get("package", []) if p["name"] == name})


def main() -> None:
    if len(sys.argv) != 2:
        die("usage: rustsec_autofix.py <out_dir>")
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)

    fixed: list[dict] = []
    remaining: list[dict] = []
    main_changed = False
    for ws in WORKSPACES:
        before = audit(ws)
        for pkg in sorted(
            {(v["package"]["name"], v["package"]["version"]) for v in before}
        ):
            spec = f"{pkg[0]}@{pkg[1]}"
            upd = subprocess.run(
                [
                    "cargo",
                    "update",
                    "--manifest-path",
                    str(ws / "Cargo.toml"),
                    "-p",
                    spec,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if upd.returncode != 0:
                print(
                    f"::warning::cargo update -p {spec} in {ws} failed:\n{upd.stderr}"
                )
        after_ids = {v["advisory"]["id"] for v in audit(ws)}
        for v in before:
            row = {
                "workspace": str(ws),
                "id": v["advisory"]["id"],
                "title": v["advisory"]["title"],
                "crate": v["package"]["name"],
                "from": v["package"]["version"],
                "patched": v["versions"]["patched"],
            }
            if row["id"] in after_ids:
                remaining.append(row)
            else:
                row["to"] = ", ".join(locked_versions(ws, row["crate"]))
                fixed.append(row)
                main_changed |= ws == pathlib.Path(".")

    lines = [
        (
            "Automated by `rustsec-autofix.yml`. It ran `cargo update -p <crate>@<version>` for "
            "each RustSec advisory in the lockfiles. Only lockfiles changed: no `Cargo.toml` "
            "edits, and every update stays within the semver ranges that the manifests allow."
        ),
        "",
        "| Lockfile | Advisory | Crate | From | To |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(fixed, key=lambda r: (r["workspace"], r["id"])):
        lock = "Cargo.lock" if r["workspace"] == "." else f"{r['workspace']}/Cargo.lock"
        lines.append(
            f"| `{lock}` | [{r['id']}](https://rustsec.org/advisories/{r['id']}) "
            f"| {r['crate']} | {r['from']} | {r['to']} |"
        )
    if remaining:
        lines += ["", "Not fixable from the lockfile (needs a manifest change):", ""]
        lines += [
            f"- {r['id']}: {r['crate']} {r['from']} in `{r['workspace']}`"
            for r in remaining
        ]
    (out / "body.md").write_text("\n".join(lines) + "\n")

    if main_changed:
        ids = sorted({r["id"] for r in fixed if r["workspace"] == "."})
        crates = sorted(
            {f"{r['crate']} {r['to']}" for r in fixed if r["workspace"] == "."}
        )
        # knope consumes every fragment at release, so the directory can be absent.
        CHANGESETS.mkdir(exist_ok=True)
        (CHANGESETS / f"{ids[0].lower()}.md").write_text(
            "---\ndefault: security\n---\n\n"
            f"#### Dependency update for {', '.join(ids)}\n\n"
            f"The lockfile moves to {', '.join(crates)}, which fixes {', '.join(ids)}.\n"
        )

    summary = {
        "fixed": sorted({r["id"] for r in fixed}),
        "remaining": sorted({r["id"] for r in remaining}),
        "main_changed": main_changed,
    }
    (out / "summary.json").write_text(json.dumps(summary))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
