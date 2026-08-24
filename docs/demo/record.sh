#!/usr/bin/env bash
# Re-record the README demo. Requires: a C compiler, docker, syft, a release
# build of scratchsmith, asciinema, and svg-term (npm i -g svg-term-cli).
#
#   docs/demo/record.sh
#
# Produces docs/demo/scratchsmith.svg — the animated SVG embedded in the README.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cc -O2 -o "$work/greet" "$here/greet.c"
cp "$here/play.sh" "$work/play.sh"
cp "$root/target/release/scratchsmith" "$work/scratchsmith"

# Fresh image each run, so the cast always shows the real pack, load, and run.
docker image rm scratchsmith/greet:packed >/dev/null 2>&1 || true

cast="$work/demo.cast"
( cd "$work" && PATH="$work:$PATH" \
    asciinema rec --overwrite --idle-time-limit 2.5 --cols 92 --rows 22 \
      --command "bash play.sh" "$cast" )

svg-term --in "$cast" --out "$here/scratchsmith.svg" --window --width 92 --height 22

echo "wrote $here/scratchsmith.svg"
