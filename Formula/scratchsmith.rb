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
  version "1.2.1"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.2.1/scratchsmith-v1.2.1-linux-amd64.tar.gz"
      sha256 "cb55bdf17c6038193a42b0d3f2aa4015bcdbe9d57fc33160f058745a2497e32d"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.2.1/scratchsmith-v1.2.1-linux-arm64.tar.gz"
      sha256 "720d507ddcb6d14130cd1750ced901ed43be232cf051adf7bff7d98395ab6cef"
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
