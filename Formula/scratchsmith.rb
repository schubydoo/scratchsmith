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
  version "1.4.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.4.0/scratchsmith-v1.4.0-linux-amd64.tar.gz"
      sha256 "98c73529d74679d2e52a680ac18da51ddc877d13bed1eaf8c3f12994c07caa8b"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.4.0/scratchsmith-v1.4.0-linux-arm64.tar.gz"
      sha256 "c0515600cdb4dee5936846fab1f604b016be4ae86fd9a595c349ea3eba0e6456"
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
