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
  version "1.7.1"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.7.1/scratchsmith-v1.7.1-linux-amd64.tar.gz"
      sha256 "2397178fe3eccbd551924a32a1155aceb232f066730dd208ea48845a7db175b4"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.7.1/scratchsmith-v1.7.1-linux-arm64.tar.gz"
      sha256 "3bc2569f143b1dddf8eadb388afcfcd5f4702b32788b4f9d41751fc7cfce04be"
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
