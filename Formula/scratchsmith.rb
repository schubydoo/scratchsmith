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
  version "2.0.2"
  license "MIT"

  on_linux do
    on_intel do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.0.2/scratchsmith-v2.0.2-linux-amd64.tar.gz"
      sha256 "5ae1155c2b985b6f093a801e443fa2d9ba6b9985ec33540502d085f1d8295438"
    end
    on_arm do
      url "https://github.com/schubydoo/scratchsmith/releases/download/v2.0.2/scratchsmith-v2.0.2-linux-arm64.tar.gz"
      sha256 "5bf02be6d7a61bb9e834a32c6789bfc014ba455fafcdfa4b8550f4dcca4b6c12"
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
