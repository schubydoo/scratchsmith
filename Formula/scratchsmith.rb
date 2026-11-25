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
  version "2.0.1"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.0.1/scratchsmith-v2.0.1-linux-amd64.tar.gz"
      sha256 "cfb0c7b7d4c133f5456124f4271579e5d05c3a92f7a2e6d39cc4ec795946427c"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.0.1/scratchsmith-v2.0.1-linux-arm64.tar.gz"
      sha256 "c41f15b87a33b78c8a7118055ebd0617fbd7ac0dd49283cbc9c1e98fa116f359"
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
