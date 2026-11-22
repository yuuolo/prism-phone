#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'This pinned server fixture requires Linux x86_64.' >&2
  exit 1
fi

base="$PWD/artifacts/vmess-servers-linux"
download_server() {
  local name="$1" url="$2" digest="$3"
  mkdir -p "$base/$name"
  curl --fail --location --max-time 60 "$url" --output "$base/$name.zip"
  printf '%s  %s\n' "$digest" "$base/$name.zip" | sha256sum --check -
  unzip -oq "$base/$name.zip" -d "$base/$name"
}

# Digests are the official release asset digests, pinned with the version.
# These independent servers are fixtures only, never APK payloads.
download_server xray \
  'https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip' \
  'b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82'
download_server v2fly \
  'https://github.com/v2fly/v2ray-core/releases/download/v5.53.0/v2ray-linux-64.zip' \
  '6bbb8aee65a57d0b12599b4b7c842b3ad0daca4436e661d94015c447cb31b4fa'
chmod +x "$base/xray/xray" "$base/v2fly/v2ray"
