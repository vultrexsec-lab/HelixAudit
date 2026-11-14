#!/usr/bin/env bash
# Install ProjectDiscovery binaries (Tier A)
set -e
BIN_DIR="$(cd "$(dirname "$0")/.." && pwd)/bin"
mkdir -p "$BIN_DIR"

install_zip () {
  local name="$1" url="$2" binname="$3"
  if [ -x "$BIN_DIR/$binname" ]; then
    echo "$binname already present"
    return 0
  fi
  echo "Downloading $name..."
  if ! curl -fsSL "$url" -o "/tmp/${name}.zip"; then
    echo "WARN: failed to download $name"
    return 0
  fi
  rm -rf "/tmp/${name}_extract"
  mkdir -p "/tmp/${name}_extract"
  unzip -o -q "/tmp/${name}.zip" -d "/tmp/${name}_extract" || true
  found=$(find "/tmp/${name}_extract" -type f -name "$binname" | head -1)
  if [ -n "$found" ]; then
    cp "$found" "$BIN_DIR/$binname"
    chmod +x "$BIN_DIR/$binname"
    echo "Installed $binname"
  else
    echo "WARN: $binname not found in archive"
  fi
}

install_zip nuclei "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip" nuclei
install_zip pdhttpx "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip" httpx
install_zip subfinder "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip" subfinder

if [ -x "$BIN_DIR/nuclei" ]; then
  echo "Updating nuclei templates..."
  "$BIN_DIR/nuclei" -update-templates -silent 2>/dev/null || \
    "$BIN_DIR/nuclei" -ut 2>/dev/null || true
fi

echo "Tools in $BIN_DIR:"
ls -la "$BIN_DIR" || true
