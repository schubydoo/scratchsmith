#!/usr/bin/env python3
"""Verify, or with ``--fix`` refresh, the release-asset sha256 pinned next to a version.

``.github/workflows/actionlint.yml`` pins actionlint by ``ACTIONLINT_VERSION`` and by the
sha256 of the downloaded tarball (``sha256sum -c`` fails the job on a mismatch). Renovate
bumps the version through the ``# renovate:`` annotation, but it cannot rewrite the sha256:
the ``github-releases`` datasource exposes the git-tag commit, not the asset's file hash.
GitHub publishes a per-asset SHA-256 (the ``digest`` field of a release asset), so this
script reads that digest and compares it with the pin.

* verify (default): a stale hash fails and the script prints the correct value.
* ``--fix``: a stale hash is rewritten in place. The self-hosted Renovate CE runs this as a
  ``postUpgradeTask`` (see ``schubydoo/renovate-config``), so the new hash lands in the
  same commit as the version bump.

Fetch and lookup errors fail in both modes, so a bump that cannot be verified never passes.
Stdlib only: the postUpgradeTask runs a bare ``python3`` with no virtualenv.
Ported from clauster's ``scripts/check_binary_dep_pins.py`` (the workflow-pin half only).

Exit codes: ``0`` every pin matches (or, with ``--fix``, now matches); ``1`` a pin is stale
(verify mode) or could not be fetched, located, or parsed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkflowPin:
    """One ``*_VERSION`` + ``*_SHA256`` release-asset pin in a workflow file."""

    path: str  # workflow file, relative to the repo root
    owner: str
    repo: str
    version_re: re.Pattern[str]  # one group: the pinned version
    sha_re: re.Pattern[str]  # one group: the pinned 64-hex sha256
    tag: Callable[[str], str]  # version -> release tag
    asset: Callable[[str], str]  # version -> downloaded asset name


PINS: tuple[WorkflowPin, ...] = (
    # The version is bare ("1.7.12"), so the tag is "v" + version. The asset name matches
    # the download URL that the workflow's run-script builds.
    WorkflowPin(
        path=".github/workflows/actionlint.yml",
        owner="rhysd",
        repo="actionlint",
        version_re=re.compile(r'ACTIONLINT_VERSION:\s*"([^"]+)"'),
        sha_re=re.compile(r'ACTIONLINT_SHA256:\s*"([0-9a-f]{64})"'),
        tag=lambda v: f"v{v}",
        asset=lambda v: f"actionlint_{v}_linux_amd64.tar.gz",
    ),
)


def fetch_release(owner: str, repo: str, tag: str) -> dict:
    """Return the GitHub release JSON for ``owner/repo`` at ``tag`` (raises on failure)."""
    api = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
    req = urllib.request.Request(api, headers={"Accept": "application/vnd.github+json"})  # noqa: S310
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https api host
        return json.load(resp)


def resolve(pin: WorkflowPin, root: Path) -> tuple[str, str, str | None]:
    """Return ``(status, detail, current_sha)`` for one pin.

    ``status`` is ``ok``, ``mismatch`` (``detail`` is the published sha256), ``warn``
    (GitHub publishes no digest for the asset), or ``error``.
    """
    try:
        text = (root / pin.path).read_text(encoding="utf-8")
    except OSError as exc:
        return "error", f"could not read {pin.path}: {exc}", None
    vmatch, smatch = pin.version_re.search(text), pin.sha_re.search(text)
    if vmatch is None or smatch is None:
        return "error", f"could not find the VERSION/SHA256 pin in {pin.path}", None
    version, current = vmatch.group(1), smatch.group(1)
    tag, asset_name = pin.tag(version), pin.asset(version)
    try:
        release = fetch_release(pin.owner, pin.repo, tag)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return "error", f"could not fetch {pin.owner}/{pin.repo}@{tag}: {exc}", current
    assets = [a for a in release.get("assets", []) if isinstance(a, dict)]
    asset = next((a for a in assets if a.get("name") == asset_name), None)
    if asset is None:
        return "error", f"release {tag} has no asset named {asset_name}", current
    digest = asset.get("digest")
    if not (isinstance(digest, str) and digest.startswith("sha256:")):
        return "warn", f"GitHub publishes no sha256 for {asset_name}", current
    published = digest.removeprefix("sha256:")
    if re.fullmatch(r"[0-9a-f]{64}", published) is None:
        return "error", f"GitHub published a malformed sha256 for {asset_name}: {digest!r}", current
    if published == current:
        return "ok", "", current
    return "mismatch", published, current


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="rewrite a stale sha256 in place")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent

    failures = 0
    fixes: dict[Path, dict[str, str]] = {}
    for pin in PINS:
        status, detail, current = resolve(pin, root)
        if status == "ok":
            print(f"OK   {pin.path}: sha256 matches GitHub's published digest")
        elif status == "warn":
            print(f"WARN {pin.path}: {detail}")
        elif status == "error" or current is None:
            print(f"FAIL {pin.path}: {detail}")
            failures += 1
        elif args.fix:
            fixes.setdefault(root / pin.path, {})[current] = detail
            print(f"FIX  {pin.path}: sha256\n       was:  {current}\n       now:  {detail}")
        else:
            print(
                f"FAIL {pin.path}: sha256 mismatch\n"
                f"       pinned:    {current}\n"
                f"       published: {detail}   <- set the *_SHA256 in this workflow to this"
            )
            failures += 1

    if fixes and failures:
        # All or nothing: never write a subset while another pin failed to verify.
        print(f"SKIP not rewriting {len(fixes)} file(s): {failures} pin(s) failed")
    elif fixes:
        # Locate every pin in every file before writing any file.
        updated: dict[Path, str] = {}
        for path, repl in fixes.items():
            text = path.read_text(encoding="utf-8")
            for old, new in repl.items():
                if text.count(old) != 1:
                    print(f"FAIL could not locate sha256 {old} exactly once in {path.name}")
                    return 1
                text = text.replace(old, new)
            updated[path] = text
        for path, text in updated.items():
            path.write_text(text, encoding="utf-8")
        print(f"wrote {sum(len(r) for r in fixes.values())} refreshed sha256 pin(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
