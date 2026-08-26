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
  version "0.2.1"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.2.1/scratchsmith-v0.2.1-linux-amd64.tar.gz"
      sha256 "3e402c2a73643581cb307bc6e707cf2948273a67a6454c2c5feca69801379f30"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.2.1/scratchsmith-v0.2.1-linux-arm64.tar.gz"
      sha256 "fc22ed5bf4b674c252a967813aed665295d463ccd2ab2019f076c0745f95415f"
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
