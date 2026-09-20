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
  version "1.3.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.3.0/scratchsmith-v1.3.0-linux-amd64.tar.gz"
      sha256 "ee917869d1e0e2201a8c221e30849ead4d653f9383ebfddaee6dd92d6be8773b"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.3.0/scratchsmith-v1.3.0-linux-arm64.tar.gz"
      sha256 "de61bb3935e4cf90a5cf2621f058aaa8f139afa1e283f6826239bb0478eb117b"
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
