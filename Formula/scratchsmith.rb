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
  version "0.2.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.2.0/scratchsmith-v0.2.0-linux-amd64.tar.gz"
      sha256 "c916c4a071a74c76c4cf3b5a9070ee5c7237bbd69f68f7b58b5977d0fd576f95"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v0.2.0/scratchsmith-v0.2.0-linux-arm64.tar.gz"
      sha256 "f70b78a3a170e954b02507aa22b18766145a0f7e2520ea77df119adecc8d72f5"
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
