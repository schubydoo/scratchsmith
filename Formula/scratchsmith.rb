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
  version "2.1.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.1.0/scratchsmith-v2.1.0-linux-amd64.tar.gz"
      sha256 "90664f994c43851f6cf1697f333059c264251b47e6bf91a2f01c232042f45d17"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.1.0/scratchsmith-v2.1.0-linux-arm64.tar.gz"
      sha256 "f55b225d9d4a87121e39227088226d27147bd6ecc6125134cde1eb27369bd4bc"
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
