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
  version "0.1.4"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.1.4/scratchsmith-v0.1.4-linux-amd64.tar.gz"
      sha256 "d7ad346605a2af4a2531350875ab3127317c6d114751f6684d7c775cdc1a7797"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.1.4/scratchsmith-v0.1.4-linux-arm64.tar.gz"
      sha256 "5edbaccff5627ef099e6d3b506cf80f67a40b3c679a8f12f44ba33b0105474d1"
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
