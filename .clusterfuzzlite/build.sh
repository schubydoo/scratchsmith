#!/bin/bash -eu
# Build the cargo-fuzz targets and stage their binaries where ClusterFuzzLite expects them.
# --debug-assertions turns on assertions during fuzzing (fault detection before deployment).
cd "$SRC/scratchsmith"
# Toolchain selection is coverage-sensitive.
#
# The base image ships nightly 1.91 (LLVM 21), older than our MSRV (Cargo.toml rust-version =
# 1.96), so fuzz builds must move off it. For the address/plain builds we roll to the current
# nightly (`rustup update`, not `install`, which no-ops when nightly exists); those never feed
# llvm-profdata, so a newer LLVM is harmless.
#
# The weekly coverage run is different: ClusterFuzzLite's runner reads the .profraw with its own
# pinned llvm-profdata (LLVM 22 -> raw profile format v10) and can only *upgrade* older formats,
# never downgrade. The current nightly is LLVM 23 (profraw v11), one ahead, so the merge dies
# ("raw profile version mismatch") and the report lands empty. Pin the coverage build to a
# nightly that clears MSRV yet is still LLVM 22 (v10), matching the runner. The pin is frozen in
# time: it always emits v10, and the runner's reader only moves up, so v10 stays upgradable.
if [ "${SANITIZER:-}" = "coverage" ]; then
  coverage_nightly="nightly-2026-08-01" # rustc 1.99, LLVM 22.1.8 — an LLVM-22 nightly >= MSRV 1.96
  rustup toolchain install "$coverage_nightly" --profile minimal >/dev/null
  export RUSTUP_TOOLCHAIN="$coverage_nightly"
else
  rustup update nightly
  export RUSTUP_TOOLCHAIN=nightly
fi
cargo fuzz build -O --debug-assertions
FUZZ_TARGET_OUTPUT_DIR="$SRC/scratchsmith/fuzz/target/x86_64-unknown-linux-gnu/release"
for f in fuzz/fuzz_targets/*.rs; do
  target="$(basename "${f%.*}")"
  cp "$FUZZ_TARGET_OUTPUT_DIR/$target" "$OUT/"
done

# Stage committed libFuzzer dictionaries (<target>.dict) so the engine knows the ld.so tokens
# ($ORIGIN, $LIB, sonames) it would otherwise have to rediscover byte-by-byte.
for d in fuzz/*.dict; do
  [ -e "$d" ] && cp "$d" "$OUT/"
done

# Seed corpora, one per format. Only a target whose entry point parses a concrete format gains
# from a seed; the Arbitrary-driven targets (resolve_graph, unpack_structured) synthesise their
# own structure, so a raw seed is noise — leave them unseeded. Generated here from the image,
# never committed. Consumed as OSS-Fuzz/ClusterFuzzLite `<target>_seed_corpus.zip`.

# ELF seeds for the two goblin parsers: a real dynamic exec plus link-variant ELFs, so mutation
# reaches resolver's interpreter/RPATH/RUNPATH/$ORIGIN/soname branches and lint's hardening
# branches (parse_elf_info sat at ~10% without them). Bare `clang` (NOT $CC/$CFLAGS) keeps them
# small, clean ELFs rather than sanitizer-instrumented ones.
elf_seed="$(mktemp -d)"
cp /usr/bin/id "$elf_seed/real-id" # real dynamic exec: interpreter + DT_NEEDED + versioned sonames
printf 'int main(void){return 0;}\n' > "$elf_seed/s.c"
clang -Wl,--disable-new-dtags,-rpath,/opt/lib     -o "$elf_seed/elf-rpath"          "$elf_seed/s.c" # RPATH
# shellcheck disable=SC2016 # $ORIGIN is a literal ELF rpath token, not a shell expansion
clang -Wl,--enable-new-dtags,-rpath,'$ORIGIN/lib' -o "$elf_seed/elf-runpath-origin" "$elf_seed/s.c" # RUNPATH + $ORIGIN
clang -shared -fPIC -Wl,-soname,libseed.so.1      -o "$elf_seed/elf-shared.so"      "$elf_seed/s.c" # ET_DYN + soname
clang -static-pie                                 -o "$elf_seed/elf-static-pie"     "$elf_seed/s.c" # static PIE: no INTERP
clang -Wl,-z,relro,-z,now                         -o "$elf_seed/elf-full-relro"     "$elf_seed/s.c" # PT_GNU_RELRO + BIND_NOW -> lint's Relro::Full
rm -f "$elf_seed/s.c"

# An OCI-archive seed for the raw `unpack` parser: a real layout whose blob digests match, so
# mutation explores the tar/gzip/index/manifest paths from a valid base instead of bouncing off
# the outer parse. Built with coreutils (sha256sum/tar/gzip), so it needs no scratchsmith binary
# at fuzz-build time. Verified locally: `scratchsmith unpack` accepts it.
oci_seed="$(mktemp -d)"
oci="$(mktemp -d)"
mkdir -p "$oci/blobs/sha256"
layer_tar="$(mktemp)"
tar -cf "$layer_tar" -C "$elf_seed" real-id
gzip -n -c "$layer_tar" > "$oci/layer.gz"
ldig="$(sha256sum "$oci/layer.gz" | cut -d' ' -f1)"
mv "$oci/layer.gz" "$oci/blobs/sha256/$ldig"
printf '{}' > "$oci/cfg"
cdig="$(sha256sum "$oci/cfg" | cut -d' ' -f1)"
mv "$oci/cfg" "$oci/blobs/sha256/$cdig"
mfst="$(printf '{"config":{"digest":"sha256:%s"},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:%s"}]}' "$cdig" "$ldig")"
printf '%s' "$mfst" > "$oci/mfst"
mdig="$(sha256sum "$oci/mfst" | cut -d' ' -f1)"
mv "$oci/mfst" "$oci/blobs/sha256/$mdig"
printf '{"manifests":[{"digest":"sha256:%s"}]}' "$mdig" > "$oci/index.json"
printf '{"imageLayoutVersion":"1.0.0"}' > "$oci/oci-layout"
( cd "$oci" && tar -cf "$oci_seed/app.oci.tar" oci-layout index.json blobs )
rm -f "$layer_tar"

# Map each target to its seed set (empty = no seed), zip, and stage in $OUT.
seed_dir_for() {
  case "$1" in
  parse_elf_info | analyze_hardening) printf '%s' "$elf_seed" ;;
  unpack) printf '%s' "$oci_seed" ;;
  *) printf '' ;;
  esac
}
for f in fuzz/fuzz_targets/*.rs; do
  target="$(basename "${f%.*}")"
  src="$(seed_dir_for "$target")"
  [ -n "$src" ] || continue
  dest="$OUT/${target}_seed_corpus.zip"
  rm -f "$dest" # zip appends; keep it idempotent if $OUT is reused
  ( cd "$src" && zip -q -r "$dest" . )
done
rm -rf "$elf_seed" "$oci_seed" "$oci"
