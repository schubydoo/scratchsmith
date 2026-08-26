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
  version "0.2.2"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.2.2/scratchsmith-v0.2.2-linux-amd64.tar.gz"
      sha256 "39c852567eec25edd15ea0d74aa73141f5f5ce473661d122c82ee941bfb4803a"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.2.2/scratchsmith-v0.2.2-linux-arm64.tar.gz"
      sha256 "4d5fe2d38395d759395b0e2a487f7194cdb3cc4f27b65303a149ef83a36c1c90"
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
