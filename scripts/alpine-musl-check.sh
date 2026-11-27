#!/bin/sh
# The Alpine CI job's in-container half (plan 025, slice 4). Run it inside alpine:3.21 with the
# static musl scratchsmith:
#
#   scripts/alpine-musl-check.sh <scratchsmith> <out-dir>
#
# 1. The musl oracle: for each dynamic program in /bin, /sbin, /usr/bin and /usr/sbin (one
#    with a PT_INTERP, read with readelf), `scratchsmith graph` must resolve exactly the files
#    that musl's own loader lists (`ld-musl-x86_64.so.1 --list`). This is the musl twin of
#    tests/differential.rs, and the main guard against a wrong musl rule: a wrong rule gives an
#    image that exits 127 while `pack` exits 0.
# 2. `pack /usr/bin/curl --oci-archive <out-dir>/curl.tar`, with a `libc` of "musl". The runner
#    then loads and runs the archive, where Docker is.
set -eu

bin=${1:?usage: alpine-musl-check.sh <scratchsmith> <out-dir>}
out=${2:?usage: alpine-musl-check.sh <scratchsmith> <out-dir>}
loader=/lib/ld-musl-x86_64.so.1

# binutils for readelf: the check reads each PT_INTERP itself, not from scratchsmith.
apk add --no-cache binutils curl jq >/dev/null

# Real paths, one per line, sorted: what musl's loader maps for "$1", the loader included.
# Its first line names the loader alone; every other line is `name => path (address)`.
oracle() {
    "$loader" --list "$1" 2>&1 | awk '
        $2 == "=>" { print $3; next }
        NR == 1 { print $1 }
    ' | while read -r path; do realpath "$path"; done | sort -u
}

# The same set from `scratchsmith graph`: every node but the root, plus the loader.
graphed() {
    printf '%s\n' "$1" | jq -r '(.nodes[1:][].id), (.interpreter // empty)' |
        while read -r path; do realpath "$path"; done | sort -u
}

checked=0
failed=0
seen=$(mktemp)
for f in /bin/* /sbin/* /usr/bin/* /usr/sbin/*; do
    # busybox applets are links to one file: check each real file once.
    [ -f "$f" ] || continue
    real=$(realpath "$f")
    if grep -qxF "$real" "$seen"; then continue; fi
    printf '%s\n' "$real" >>"$seen"
    # An ELF only. A script has no loader to ask.
    [ "$(head -c 4 "$real" | od -An -c | tr -d ' ')" = '177ELF' ] || continue
    # A static program has no loader, and nothing to compare. Decide that from the ELF, not
    # from scratchsmith: a resolver that wrongly calls a dynamic program static must fail here.
    interp=$(readelf -lW "$real" 2>/dev/null |
        sed -n 's/.*\[Requesting program interpreter: \(.*\)\]$/\1/p')
    [ -n "$interp" ] || continue
    checked=$((checked + 1))
    json=$("$bin" graph --format json "$real" 2>/dev/null) || {
        echo "FAIL $real: scratchsmith graph exited non-zero"
        "$bin" graph "$real" || true
        failed=$((failed + 1))
        continue
    }
    if [ -z "$(printf '%s\n' "$json" | jq -r '.interpreter // empty')" ]; then
        echo "FAIL $real: PT_INTERP is $interp, but scratchsmith graph reports no interpreter"
        failed=$((failed + 1))
        continue
    fi
    libc=$(printf '%s\n' "$json" | jq -r '.libc')
    missing=$(printf '%s\n' "$json" | jq -r '.missing | join(" ")')
    want=$(oracle "$real")
    got=$(graphed "$json")
    if [ "$libc" != musl ] || [ -n "$missing" ] || [ "$want" != "$got" ]; then
        echo "FAIL $real: libc=$libc missing=[$missing]"
        echo "  musl --list: $(echo "$want" | tr '\n' ' ')"
        echo "  graph:       $(echo "$got" | tr '\n' ' ')"
        failed=$((failed + 1))
    fi
done
rm -f "$seen"
echo "musl oracle: $checked dynamic programs checked, $failed failed"
# Alpine's base has a handful of dynamic programs, and curl adds one more. Zero checked means
# the walk found none, which is a broken check, not a pass.
[ "$checked" -gt 0 ] || { echo "the oracle checked no program"; exit 1; }
[ "$failed" -eq 0 ]

report=$("$bin" pack --format json --oci-archive "$out/curl.tar" /usr/bin/curl)
printf '%s\n' "$report" | jq -e '.libc == "musl" and .interpreter == "/lib/ld-musl-x86_64.so.1"' >/dev/null || {
    echo "the curl pack did not report musl: $report"
    exit 1
}
echo "packed /usr/bin/curl into $out/curl.tar"
