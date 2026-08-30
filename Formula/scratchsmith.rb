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
  version "1.1.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.1.0/scratchsmith-v1.1.0-linux-amd64.tar.gz"
      sha256 "717dd341c08bc9bb6fe4f7e42284ec6a3555f044dea919f4af7c3a30073f388b"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.1.0/scratchsmith-v1.1.0-linux-arm64.tar.gz"
      sha256 "03160ec76049a86146f286897ec5414f557731d671c28bf91408ce70f00cad01"
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
