#!/usr/bin/env python3
"""Regenerate Formula/scratchsmith.rb (version + per-arch url/sha256) from a release.

Usage: bump_packaging.py <version> <checksums_file>
  <version>        bare X.Y.Z (no leading 'v').
  <checksums_file> the release's checksums.txt — the CALLER is expected to have
                   cosign-verified it first (packaging-bump.yml does).

Fail-closed: exits non-zero on a bad version, a missing per-arch checksum, or a bump
that didn't take. A missing formula file is a soft skip (nothing to bump yet), so this
can run before the Homebrew packaging has landed on main.
"""
import pathlib
import re
import sys
from typing import NoReturn

REPO = "schubydoo/scratchsmith"
FORMULA = pathlib.Path("Formula/scratchsmith.rb")
ARCHES = ("linux-amd64", "linux-arm64")


def die(msg: str) -> NoReturn:
    sys.exit(f"bump_packaging: {msg}")


def main() -> None:
    if len(sys.argv) != 3:
        die("usage: bump_packaging.py <version> <checksums_file>")
    version = sys.argv[1].lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        die(f"bad version {version!r}; expected X.Y.Z")
    if not FORMULA.is_file():
        print(f"{FORMULA} absent — nothing to bump")
        return

    checks = pathlib.Path(sys.argv[2]).read_text()
    hashes = {}
    for arch in ARCHES:
        m = re.search(
            rf"^([0-9a-f]{{64}})\s+scratchsmith-v{re.escape(version)}-{re.escape(arch)}\.tar\.gz$",
            checks,
            re.MULTILINE,
        )
        if not m:
            die(f"no checksum for scratchsmith-v{version}-{arch}.tar.gz in the manifest")
        hashes[arch] = m.group(1)

    text = FORMULA.read_text()
    text, n = re.subn(r'version "\d+\.\d+\.\d+"', f'version "{version}"', text, count=1)
    if n != 1:
        die("could not find the version line to bump")
    for arch, h in hashes.items():
        pattern = (
            rf'url "https://github\.com/{re.escape(REPO)}/releases/download/'
            rf'v\d+\.\d+\.\d+/scratchsmith-v\d+\.\d+\.\d+-{re.escape(arch)}\.tar\.gz"\n'
            r'(\s*)sha256 "[0-9a-f]{64}"'
        )
        repl = (
            f'url "https://github.com/{REPO}/releases/download/'
            f'v{version}/scratchsmith-v{version}-{arch}.tar.gz"\n'
            rf'\g<1>sha256 "{h}"'
        )
        text, n = re.subn(pattern, repl, text, count=1)
        if n != 1:
            die(f"could not rewrite the {arch} url/sha256 block")

    FORMULA.write_text(text)
    # Prove the bump took, so a silent no-op can never ship a stale formula.
    final = FORMULA.read_text()
    if f'version "{version}"' not in final or any(h not in final for h in hashes.values()):
        die("post-write verification failed; formula not updated cleanly")
    print(f"bumped {FORMULA} -> {version}")


if __name__ == "__main__":
    main()
