#!/usr/bin/env python3
"""Lockfile-only fix for RustSec advisories, for rustsec-autofix.yml.

Usage: rustsec_autofix.py <out_dir>

For each workspace lockfile (Cargo.lock, fuzz/Cargo.lock) it runs `cargo audit`, then
`cargo update -p <crate>@<vulnerable version>` for every hit, then audits again. Renovate
cannot do this: its OSV alerts cover direct deps only, and a crate pinned only in a
lockfile waits for the weekly lockFileMaintenance.

`cargo update -p` stays inside the semver ranges that Cargo.toml allows, so it never
edits a manifest. Every advisory in the second audit is reported as remaining, never
forced: one whose fix needs a manifest change, and one that the update itself brought in.

Writes into <out_dir>: `body.md` (PR body) and `summary.json`
({"fixed": [...], "remaining": [...]}). If an advisory in the main lockfile was fixed,
also writes `.changeset/<first advisory id>.md` in the repo. The name is per advisory,
so a later run never overwrites an unreleased fragment from an earlier one.
"""

import json
import pathlib
import subprocess
import sys
import time
import tomllib
from typing import NoReturn

WORKSPACES = (pathlib.Path("."), pathlib.Path("fuzz"))
CHANGESETS = pathlib.Path(".changeset")


def die(msg: str) -> NoReturn:
    sys.exit(f"rustsec_autofix: {msg}")


def audit(ws: pathlib.Path) -> list[dict]:
    """The vulnerability list of one lockfile. Warnings (unmaintained, yanked) are ignored."""
    # cargo audit exits 1 when it finds something, so the exit code is no error signal.
    # A run that produced no JSON is one. The advisory-db fetch flakes now and then
    # (AGENTS.md), so retry once before failing a scheduled run over it.
    for attempt in (1, 2):
        proc = subprocess.run(
            ["cargo", "audit", "--json", "--file", str(ws / "Cargo.lock")],
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            return json.loads(proc.stdout)["vulnerabilities"]["list"]
        except json.JSONDecodeError:
            if attempt == 1:
                time.sleep(30)
    die(f"cargo audit on {ws / 'Cargo.lock'} gave no JSON:\n{proc.stderr}")


def new_versions(ws: pathlib.Path, name: str, old: str) -> list[str]:
    """Locked versions of `name` other than the vulnerable one, i.e. what it moved to."""
    lock = tomllib.loads((ws / "Cargo.lock").read_text())
    return sorted(
        {
            p["version"]
            for p in lock.get("package", [])
            if p["name"] == name and p["version"] != old
        }
    )


def row(ws: pathlib.Path, v: dict) -> dict:
    return {
        "workspace": str(ws),
        "id": v["advisory"]["id"],
        "crate": v["package"]["name"],
        "from": v["package"]["version"],
    }


def main() -> None:
    if len(sys.argv) != 2:
        die("usage: rustsec_autofix.py <out_dir>")
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)

    fixed: list[dict] = []
    remaining: list[dict] = []
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
        # Everything the second audit finds is remaining, including an advisory that the
        # update brought in. Subtracting it from the first audit would drop that one.
        after = audit(ws)
        remaining += [row(ws, v) for v in after]
        after_ids = {v["advisory"]["id"] for v in after}
        for v in before:
            if v["advisory"]["id"] not in after_ids:
                r = row(ws, v)
                r["to"] = ", ".join(new_versions(ws, r["crate"], r["from"]))
                fixed.append(r)

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
        lines += [
            "",
            (
                "Still in the lockfiles after the update (needs a manifest change, or the "
                "update brought it in):"
            ),
            "",
        ]
        lines += [
            f"- {r['id']}: {r['crate']} {r['from']} in `{r['workspace']}`"
            for r in sorted(remaining, key=lambda r: (r["workspace"], r["id"]))
        ]
    (out / "body.md").write_text("\n".join(lines) + "\n")

    main_fixed = [r for r in fixed if r["workspace"] == "."]
    if main_fixed:
        ids = sorted({r["id"] for r in main_fixed})
        crates = sorted({f"{r['crate']} {r['to']}" for r in main_fixed})
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
    }
    (out / "summary.json").write_text(json.dumps(summary))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
