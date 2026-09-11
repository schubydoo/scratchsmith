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
  version "1.2.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.2.0/scratchsmith-v1.2.0-linux-amd64.tar.gz"
      sha256 "c24dacfcdf61cd492360ebfdcf05d2da4988ac08c2693b0db5862ac45c497454"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.2.0/scratchsmith-v1.2.0-linux-arm64.tar.gz"
      sha256 "e0507a8e97245111fb3eedd578a4e0b91eeeffbfe5cdc1076720ac5689666baa"
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
