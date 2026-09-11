#!/usr/bin/env bash
# The scripted session asciinema records. Types each command behind a prompt at
# human speed, pauses so the output can be read, then runs it. Kept honest:
# SBOM + strip + smoke + size + a real run — no signing (not shipped yet).
#
# Pacing knobs (seconds): CHAR = per-keystroke, PRE = pause after typing before
# running, POST = pause after the command's output so it can be read. Bump these
# to slow the cast down; keep record.sh's --idle-time-limit >= POST or the pause
# is clipped.
set -euo pipefail

PROMPT='\033[1;32m$\033[0m '
CHAR=0.055
PRE=0.7
POST=2.2

type_cmd() {
    local line=$1 i
    printf '%b' "$PROMPT"
    for ((i = 0; i < ${#line}; i++)); do
        printf '%s' "${line:i:1}"
        sleep "$CHAR"
    done
    printf '\n'
}

demo() {
    type_cmd "$1"
    sleep "$PRE"
    bash -c "$1"
    printf '\n'
    sleep "$POST"
}

demo 'file greet'
demo 'scratchsmith pack --sbom --strip --smoke ./greet'
demo "docker image ls scratchsmith/greet:packed --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}'"
demo 'docker run --rm scratchsmith/greet:packed'

# Hold on the final frame — a fresh prompt plus a long pause — so the run output
# (the whole payoff) stays readable before the SVG loops back to the start.
# asciinema timestamps terminal OUTPUT, not sleeps, so the pause must be bracketed
# by writes or the cast simply ends at the prompt and the hold never lands.
printf '%b' "$PROMPT"
sleep 4
printf ' \b'
