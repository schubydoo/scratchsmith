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
  version "1.5.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.5.0/scratchsmith-v1.5.0-linux-amd64.tar.gz"
      sha256 "8bdcb6efb272441148d56faa8a53bdde95f3f3b057353aa369e134c99464c475"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.5.0/scratchsmith-v1.5.0-linux-arm64.tar.gz"
      sha256 "5913414ead5f04e4969fa9c83a99c9503c11cfab981a94d0830a7aa56e43faa8"
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
