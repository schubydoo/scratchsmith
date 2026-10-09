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
  version "1.7.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.7.0/scratchsmith-v1.7.0-linux-amd64.tar.gz"
      sha256 "5ee8545964190f2e387fb83d1dc6d3c5f07f8163ed00090b8b4f3c67c81a82fd"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.7.0/scratchsmith-v1.7.0-linux-arm64.tar.gz"
      sha256 "9899f20a781edbf02770ad2e663475e6ca04cfbe21d1b90e16db8f23ab068a1e"
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
