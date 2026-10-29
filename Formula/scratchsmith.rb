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
  version "1.9.0"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.9.0/scratchsmith-v1.9.0-linux-amd64.tar.gz"
      sha256 "63da33bc7bd81854c7b909a6a8b80883bd153f5ecd94b7e83e7291b9d4486ef6"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v1.9.0/scratchsmith-v1.9.0-linux-arm64.tar.gz"
      sha256 "5e9c9de63e23f271c415593ca24ddb58a18fb9400015fba630f4fe51ef9c37da"
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
