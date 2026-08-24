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
  version "0.1.3"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.1.3/scratchsmith-v0.1.3-linux-amd64.tar.gz"
      sha256 "79bb7536bbc8639e1d100e945f6ed0191aed26a15fae940ea6045a3a0eb9c833"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.1.3/scratchsmith-v0.1.3-linux-arm64.tar.gz"
      sha256 "c3a3bda5ef2c5e53fa7757fd0281fec7eb454cbab14067dfc3ce4a0e16d491fd"
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
