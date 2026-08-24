#!/usr/bin/env bash
# The scripted session asciinema records. Prints each command behind a prompt,
# pauses briefly so the cast reads at human speed, then runs it. Kept honest:
# SBOM + strip + smoke + size + a real run — no signing (not shipped yet).
set -euo pipefail

PROMPT='\033[1;32m$\033[0m '

demo() {
    printf '%b%s\n' "$PROMPT" "$1"
    sleep 0.8
    bash -c "$1"
    printf '\n'
    sleep 1.2
}

demo 'file greet'
demo 'scratchsmith pack --sbom --strip --smoke ./greet'
demo "docker image ls scratchsmith/greet:packed --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}'"
demo 'docker run --rm scratchsmith/greet:packed'
