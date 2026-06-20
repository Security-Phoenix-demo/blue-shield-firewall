#!/usr/bin/env bash
# Phoenix Security Blue Shield - Firewall — userland installer (macOS / Linux)
#
#   curl -sSfL https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/scripts/install.sh | bash
#   curl -sSfL ... | bash -s -- --version v0.1.0 --prefix /usr/local
#
# Handles unsigned-binary gotchas:
#   - macOS Gatekeeper: ad-hoc signs the binary so Launch Services accepts it.
#   - Linux: nothing special; just chmod +x.
#
# Windows users: see scripts/install.ps1 (PowerShell).

set -euo pipefail

REPO="Security-Phoenix-demo/phoenix-firewall"
VERSION=""                   # empty → latest
PREFIX="${PHOENIX_INSTALL_PREFIX:-$HOME/.local/bin}"
TMPDIR=""

cleanup() { [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; }
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --prefix)  PREFIX="$2"; shift 2 ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

# -----------------------------------------------------------------------------
# Detect OS / arch
# -----------------------------------------------------------------------------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  darwin|linux) ;;
  *) echo "Unsupported OS: $OS — use scripts/install.ps1 on Windows." >&2; exit 1 ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

# -----------------------------------------------------------------------------
# Resolve version
# -----------------------------------------------------------------------------
if [[ -z "$VERSION" ]]; then
  echo "Resolving latest release..."
  VERSION="$(curl -sf "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')"
  if [[ -z "$VERSION" ]]; then
    echo "ERROR: could not resolve latest tag from ${REPO}." >&2
    echo "If no releases are published yet, pass --version v0.x.y manually or build from source." >&2
    exit 1
  fi
fi
VERSION_NO_V="${VERSION#v}"

ASSET="phoenix-firewall_${VERSION_NO_V}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

TMPDIR="$(mktemp -d)"
echo "Downloading ${URL}"
curl -sSfL -o "$TMPDIR/$ASSET" "$URL"

# -----------------------------------------------------------------------------
# Verify checksum
# -----------------------------------------------------------------------------
echo "Verifying SHA-256..."
curl -sSfL -o "$TMPDIR/checksums.txt" "$SUMS_URL"
EXPECTED="$(grep "  ${ASSET}\$" "$TMPDIR/checksums.txt" | awk '{print $1}')"
if [[ -z "$EXPECTED" ]]; then
  echo "ERROR: ${ASSET} not found in checksums.txt — aborting." >&2; exit 1
fi
if command -v sha256sum >/dev/null; then
  ACTUAL="$(sha256sum "$TMPDIR/$ASSET" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$TMPDIR/$ASSET" | awk '{print $1}')"
fi
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  echo "ERROR: SHA-256 mismatch! expected $EXPECTED, got $ACTUAL" >&2; exit 1
fi
echo "Checksum verified."

# -----------------------------------------------------------------------------
# Extract + install
# -----------------------------------------------------------------------------
tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"
mkdir -p "$PREFIX"
mv "$TMPDIR/phoenix-firewall" "$PREFIX/phoenix-firewall"
chmod +x "$PREFIX/phoenix-firewall"

# -----------------------------------------------------------------------------
# macOS Gatekeeper workaround for unsigned binaries
# -----------------------------------------------------------------------------
if [[ "$OS" == "darwin" ]]; then
  echo "Applying macOS unsigned-binary workarounds..."
  # 1. Strip the quarantine xattr that Safari/curl-via-browser would set.
  /usr/bin/xattr -d com.apple.quarantine "$PREFIX/phoenix-firewall" 2>/dev/null || true
  # 2. Ad-hoc sign so Launch Services / amfi-trust-cache will load it without
  #    Apple Developer ID. This does NOT trigger notarization checks; it just
  #    satisfies the "binary must be signed (even ad-hoc)" rule on macOS 11+.
  if command -v codesign >/dev/null; then
    /usr/bin/codesign --force --sign - "$PREFIX/phoenix-firewall" 2>/dev/null \
      || echo "WARNING: ad-hoc codesign failed; you may need to run 'xattr -d com.apple.quarantine' and approve in System Settings → Privacy & Security."
  fi
fi

echo
echo "Installed phoenix-firewall ${VERSION} → $PREFIX/phoenix-firewall"
if [[ ":$PATH:" != *":$PREFIX:"* ]]; then
  echo "Add to PATH:  export PATH=\"$PREFIX:\$PATH\""
fi
echo
echo "Next steps:"
echo "  phoenix-firewall version"
echo "  phoenix-firewall init"
echo "  phoenix-firewall enroll --api-key <your-bootstrap-token>"
