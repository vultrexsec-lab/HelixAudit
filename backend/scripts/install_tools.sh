#!/usr/bin/env bash
set -e
BIN_DIR="$(cd "$(dirname "$0")/.." && pwd)/bin"
mkdir -p "$BIN_DIR"
cd /tmp

install_zip () {
  local name="$1" url="$2" binname="$3"
  if [ -x "$BIN_DIR/$binname" ]; then
    echo "$binname already present"
    return
  fi
  echo "Downloading $name..."
  curl -sL "$url" -o "/tmp/${name}.zip"
  unzip -o -q "/tmp/${name}.zip" -d "/tmp/${name}_extract"
  find "/tmp/${name}_extract" -type f -name "$binname" -exec cp {} "$BIN_DIR/$binname" \;
  chmod +x "$BIN_DIR/$binname" || true
  echo "Installed $binname"
}

install_zip nuclei "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip" nuclei
install_zip pdhttpx "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip" httpx
install_zip subfinder "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip" subfinder

"$BIN_DIR/nuclei" -update-templates -silent 2>/dev/null || true
echo "Tools ready in $BIN_DIR"
