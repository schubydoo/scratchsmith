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
  version "1.5.1"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.5.1/scratchsmith-v1.5.1-linux-amd64.tar.gz"
      sha256 "3cc93aa731c42d5848bbf170eedb33b999fbb9c8b28c7245f3d571cee3ae1451"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.5.1/scratchsmith-v1.5.1-linux-arm64.tar.gz"
      sha256 "ed14285e4687f3427b491170b81ad1d150e4ca74b9d09a3aa3998fec86abc117"
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
