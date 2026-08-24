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
  version "0.1.2"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.1.2/scratchsmith-v0.1.2-linux-amd64.tar.gz"
      sha256 "35f62113b8214a4e40686f0863e7cd0ac6b1126df7578d2a23f9b45824c9733c"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.1.2/scratchsmith-v0.1.2-linux-arm64.tar.gz"
      sha256 "d0752bf2135456ae4a6da9b319d35051610b8d1182f9a4be0aaf5ca6aefe7109"
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
