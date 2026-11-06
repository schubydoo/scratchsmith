# Homebrew formula for the signed scratchsmith binary (Linux only).
#
#   brew install schubydoo/scratchsmith/scratchsmith
#
# scratchsmith packs a prebuilt dynamic glibc *Linux* ELF into a FROM scratch OCI
# image, so it is Linux-only (Homebrew on Linux / WSL). Version + checksums are
# auto-bumped per release by packaging-bump.yml in the main repo, from the release
# checksums.txt; this tap mirrors that canonical file via sync-formula.yml.
class Scratchsmith < Formula
  desc "Pack a dynamic glibc Linux binary into a minimal non-root scratch container"
  homepage "https://github.com/schubydoo/scratchsmith"
  version "2.0.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.0.0/scratchsmith-v2.0.0-linux-amd64.tar.gz"
      sha256 "bfa0ac4bfaf96238601fdaea183906a989079e50af6112243303fd061e7bd0b7"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.0.0/scratchsmith-v2.0.0-linux-arm64.tar.gz"
      sha256 "c63a5ff29711814098418156483ddf086ae347df225f24ed464a29f0b03c0b15"
    end
  end

  def install
    # The tarball unpacks to a single scratchsmith-v<ver>-linux-<arch>/ directory;
    # Homebrew strips that leading component, so the binary is at the CWD root.
    bin.install "scratchsmith"
  end

  test do
    assert_match "scratchsmith", shell_output("#{bin}/scratchsmith --version")
  end
end
