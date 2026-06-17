#!/usr/bin/env sh
# NexusID Sync Agent — Linux/macOS installer.
#
#   curl -fsSL https://raw.githubusercontent.com/adroitts/nexusid-agent/main/packaging/install.sh | sh
#
# Detects OS/arch, downloads the matching release tarball from GitHub, verifies its SHA-256, and
# installs the binary to a directory on PATH. Override the version with NEXUS_AGENT_VERSION.
set -eu

repo="adroitts/nexusid-agent"
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)
    case "$arch" in
      x86_64|amd64) asset="linux-x86_64" ;;
      *) echo "Unsupported Linux arch: $arch (only x86_64 is published)"; exit 1 ;;
    esac ;;
  Darwin)
    case "$arch" in
      arm64) asset="macos-arm64" ;;
      x86_64) asset="macos-x86_64" ;;
      *) echo "Unsupported macOS arch: $arch"; exit 1 ;;
    esac ;;
  *) echo "Unsupported OS: $os"; exit 1 ;;
esac

version="${NEXUS_AGENT_VERSION:-}"
if [ -z "$version" ]; then
  version="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
fi

file="nexus-agent-${version}-${asset}.tar.gz"
base="https://github.com/$repo/releases/download/$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $file ..."
curl -fsSL "$base/$file" -o "$tmp/$file"

# Verify SHA-256 (sidecar starts with the hash).
if curl -fsSL "$base/$file.sha256" -o "$tmp/$file.sha256" 2>/dev/null; then
  expected="$(awk '{print $1}' "$tmp/$file.sha256")"
  if command -v shasum >/dev/null 2>&1; then actual="$(shasum -a 256 "$tmp/$file" | awk '{print $1}')";
  else actual="$(sha256sum "$tmp/$file" | awk '{print $1}')"; fi
  if [ -n "$expected" ] && [ "$expected" != "$actual" ]; then
    echo "Checksum mismatch (expected $expected, got $actual)"; exit 1
  fi
  echo "Checksum verified."
fi

tar -xzf "$tmp/$file" -C "$tmp"

# Prefer /usr/local/bin if writable, else ~/.local/bin.
if [ -w /usr/local/bin ] 2>/dev/null; then dest="/usr/local/bin"; else dest="$HOME/.local/bin"; mkdir -p "$dest"; fi
install -m 0755 "$tmp/nexus-agent" "$dest/nexus-agent"

echo ""
echo "nexus-agent $version installed to $dest/nexus-agent"
case ":$PATH:" in *":$dest:"*) ;; *) echo "Add $dest to your PATH to run it." ;; esac
echo "Run:  nexus-agent --help"
