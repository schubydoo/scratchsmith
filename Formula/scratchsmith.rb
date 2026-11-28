# Homebrew formula for the signed scratchsmith binary (Linux only).
#
#   brew install schubydoo/scratchsmith/scratchsmith
#
# scratchsmith packs a prebuilt dynamic *Linux* ELF (glibc, or musl on x86_64) into a FROM scratch OCI
# image, so it is Linux-only (Homebrew on Linux / WSL). Version + checksums are
# auto-bumped per release by packaging-bump.yml in the main repo, from the release
# checksums.txt; this tap mirrors that canonical file via sync-formula.yml.
class Scratchsmith < Formula
  desc "Pack a dynamic glibc or musl Linux binary into a minimal non-root scratch container"
  homepage "https://github.com/schubydoo/scratchsmith"
  version "2.3.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.3.0/scratchsmith-v2.3.0-linux-amd64.tar.gz"
      sha256 "2240a98be0097022718a60373ae45e895d18dca61cf5cb858dcf3846ede9ecaa"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.3.0/scratchsmith-v2.3.0-linux-arm64.tar.gz"
      sha256 "fcc7314b9f43336473217f66a74e35815c3f3fcfbd0bbb2e2a960af4aa9053af"
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
