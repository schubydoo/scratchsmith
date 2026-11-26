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
  version "2.0.3"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.0.3/scratchsmith-v2.0.3-linux-amd64.tar.gz"
      sha256 "f61483ed8f29029f28217ac4d315051db7148c04c8ccb08fd6fc0568a90c6c30"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.0.3/scratchsmith-v2.0.3-linux-arm64.tar.gz"
      sha256 "8a2512b84770fd3927344256bf5152c6806004566fd09dd6463ceda4d7e8b368"
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
