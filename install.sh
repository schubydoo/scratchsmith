#!/usr/bin/env bash
# Scratchsmith installer. Downloads the signed release binary for Linux (amd64/arm64),
# verifies it against the cosign-signed checksums.txt, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/schubydoo/scratchsmith/main/install.sh | bash
#
# Env overrides:
#   VERSION   release tag to install (default: latest), e.g. VERSION=v1.0.0
#   BIN_DIR   install directory (default: /usr/local/bin as root, else ~/.local/bin)
#
# Scratchsmith is LINUX-ONLY: it stages a Linux glibc rootfs (Unix symlinks + mode bits,
# host NSS/ld.so.cache, `ldconfig`), so it does not run on macOS or native Windows. On
# those, run it inside a Linux container or WSL2.
set -euo pipefail

REPO="schubydoo/scratchsmith"
TOOL="scratchsmith"

# --- output helpers ----------------------------------------------------------
if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else
  B=""; G=""; Y=""; R=""; N=""
fi
info() { printf '%s[info]%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
Scratchsmith installer.

  (no argument)   download, verify, and install the latest release
  --uninstall     remove an installed scratchsmith binary
  --help          show this message

Env: VERSION=vX.Y.Z (tag to install), BIN_DIR=/path (install / lookup directory).

  install:   curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash
  uninstall: curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash -s -- --uninstall
EOF
}

# Remove an installed binary. install.sh only ever places the binary (not completions
# or config), so uninstall removes exactly that. Looks in BIN_DIR, then PATH, then the
# two default directories.
uninstall() {
  target=""
  if [ -n "${BIN_DIR:-}" ] && [ -x "${BIN_DIR}/${TOOL}" ]; then
    target="${BIN_DIR}/${TOOL}"
  elif have "$TOOL"; then
    target="$(command -v "$TOOL")"
  else
    for d in /usr/local/bin "$HOME/.local/bin"; do
      if [ -x "${d}/${TOOL}" ]; then
        target="${d}/${TOOL}"
        break
      fi
    done
  fi
  [ -n "$target" ] || die "no ${TOOL} install found (checked \$BIN_DIR, PATH, /usr/local/bin, ~/.local/bin)"
  info "removing ${target}…"
  if [ -w "$(dirname "$target")" ]; then
    rm -f "$target"
  elif have sudo; then
    sudo rm -f "$target"
  else
    die "no write access to $(dirname "$target") and no sudo; remove ${target} manually"
  fi
  ok "uninstalled ${TOOL} (removed ${target})"
}

case "${1:-}" in
  --uninstall | uninstall) uninstall; exit 0 ;;
  --help | -h | help) usage; exit 0 ;;
  "") : ;;
  *) die "unknown argument '$1'; use --uninstall, --help, or no argument to install" ;;
esac

# --- platform ----------------------------------------------------------------
os="$(uname -s)"
[ "$os" = "Linux" ] || die "Scratchsmith is Linux-only (it stages a Linux glibc rootfs and needs ldconfig); detected '$os'. On macOS/Windows, run it inside a Linux container or WSL2."

case "$(uname -m)" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) die "unsupported architecture '$(uname -m)' (scratchsmith ships linux amd64 and arm64)" ;;
esac

# --- prerequisites -----------------------------------------------------------
have tar || die "need 'tar' to extract the release"
have sha256sum || die "need 'sha256sum' to verify the download"
if have curl; then
  fetch() { curl -fsSL "$1"; }
  download() { curl -fsSL "$1" -o "$2"; }
elif have wget; then
  fetch() { wget -qO- "$1"; }
  download() { wget -qO "$2" "$1"; }
else
  die "need 'curl' or 'wget' to download the release"
fi

# --- resolve the version -----------------------------------------------------
tag="${VERSION:-}"
if [ -z "$tag" ]; then
  info "resolving the latest release…"
  tag="$(fetch "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')"
  [ -n "$tag" ] || die "could not resolve the latest release tag; set VERSION=vX.Y.Z"
fi
base="https://github.com/${REPO}/releases/download/${tag}"
tarball="scratchsmith-${tag}-linux-${arch}.tar.gz"

# --- download + verify -------------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "downloading ${tarball} (${tag})…"
download "${base}/${tarball}" "${tmp}/${tarball}" || die "download failed: ${base}/${tarball}"
download "${base}/checksums.txt" "${tmp}/checksums.txt" || die "could not fetch checksums.txt"

info "verifying the SHA-256 against the release checksums…"
( cd "$tmp" && grep " ${tarball}\$" checksums.txt | sha256sum -c - ) \
  || die "checksum verification failed for ${tarball}"
ok "checksum verified"

# Verify the checksums file is itself cosign-signed by the release workflow. A SHA-256
# match alone is no protection against a tampered mirror — an attacker who swaps the
# tarball swaps checksums.txt to match — so the cosign signature is the real check, and a
# verification FAILURE aborts (it is not a warning). A genuinely absent cosign or an
# unavailable signature bundle is a documented degradation to checksum-only.
if ! have cosign; then
  warn "cosign not installed — verified the SHA-256 only. Install cosign for full signature + provenance checks (see the README 'Verifying releases')."
elif ! download "${base}/checksums.txt.sigstore.json" "${tmp}/checksums.txt.sigstore.json" 2>/dev/null; then
  warn "could not fetch the cosign signature bundle (checksums.txt.sigstore.json) — verified the SHA-256 only."
elif ( cd "$tmp" && cosign verify-blob checksums.txt \
        --bundle checksums.txt.sigstore.json \
        --certificate-identity-regexp "^https://github\.com/${REPO}/\.github/workflows/knope-release\.yml@" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 ); then
  ok "cosign signature verified"
else
  die "cosign signature verification FAILED for checksums.txt — refusing to install a possibly-tampered binary. Re-download, or (at your own risk) uninstall cosign to fall back to checksum-only."
fi

# --- install -----------------------------------------------------------------
tar -xzf "${tmp}/${tarball}" -C "$tmp"
src="${tmp}/scratchsmith-${tag}-linux-${arch}/${TOOL}"
[ -f "$src" ] || die "unexpected archive layout: ${src} not found"

if [ "$(id -u)" = "0" ]; then
  bin_dir="${BIN_DIR:-/usr/local/bin}"
else
  bin_dir="${BIN_DIR:-$HOME/.local/bin}"
fi
mkdir -p "$bin_dir"

if [ -w "$bin_dir" ]; then
  install -m 0755 "$src" "${bin_dir}/${TOOL}"
elif have sudo; then
  sudo install -m 0755 "$src" "${bin_dir}/${TOOL}"
else
  die "no write access to ${bin_dir} and no sudo; set BIN_DIR to a writable directory"
fi
ok "installed ${TOOL} ${tag} to ${bin_dir}/${TOOL}"

# --- verify + PATH note ------------------------------------------------------
"${bin_dir}/${TOOL}" --version >/dev/null 2>&1 || die "installed binary did not run: ${bin_dir}/${TOOL} --version failed"
case ":${PATH}:" in
  *":${bin_dir}:"*) : ;;
  *) warn "${bin_dir} is not on your PATH — add it, e.g.: export PATH=\"${bin_dir}:\$PATH\"" ;;
esac
ok "Installation complete! Run 'scratchsmith doctor' to check optional tools."
