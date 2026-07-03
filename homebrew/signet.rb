# Canonical Homebrew formula for signet, the cross-platform Go binary for
# hardware-rooted machine identity. This is the source of truth; copy it into the
# Homebrew tap repo (poodle64/homebrew-tap, as `Formula/signet.rb`) so users can
# `brew install poodle64/tap/signet`. Bump `version` and the sha256s when a new
# signet release is cut (the .sha256 files are published alongside each release
# tarball).
#
# SECURE ENCLAVE: the SE backend works on the pre-built release binary (unsigned/ad-hoc).
# It uses CryptoKit's self-stored-key-blob model — the Enclave's opaque hardware-wrapped
# blob is stored in a file (~/.signet/), the keychain is never
# touched, and no code-signing entitlement is required. All three backends work unsigned.
class Signet < Formula
  desc "Single Go binary for hardware-rooted machine identity; TPM, PIV, and Secure Enclave all work on the unsigned release binary"
  homepage "https://github.com/poodle64/signet"
  version "2026.6.5"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/poodle64/signet/releases/download/v#{version}/signet-#{version}-darwin-arm64.tar.gz"
      sha256 "6199e318ae5e7098b0b4992ee162e0f4f2ce5a8f0d0146f641b35e9edc83676b"
    end

    on_intel do
      # darwin/amd64 is not yet built; add when the matrix runner is added to the release workflow.
      odie "signet: no release artifact for macOS Intel (darwin/amd64) yet."
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/poodle64/signet/releases/download/v#{version}/signet-#{version}-linux-amd64.tar.gz"
      sha256 "0e18e743926d09995a7e17c3d0e57e0ef7acccb8879f4bf61d9a84a02549ef95"
    end

    on_arm do
      # linux/arm64 is not yet built; add when the matrix runner is added to the release workflow.
      odie "signet: no release artifact for Linux ARM64 (linux/arm64) yet."
    end
  end

  def install
    bin.install "signet"
  end

  test do
    # With no arguments the CLI prints its help block to stdout and exits 0;
    # an unknown subcommand exits 1 naming the failure.
    assert_match "Usage", shell_output("#{bin}/signet")
    assert_match "unknown subcommand", shell_output("#{bin}/signet nonsense 2>&1", 1)
  end
end
