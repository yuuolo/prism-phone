#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/prepare-vmess-servers.sh"

# Xray's accepted AEAD body modes, including the 8 KiB UDP probe.
for transport in tcp ws; do
export PRISM_VMESS_TRANSPORT="$transport"
PRISM_VMESS_SERVER_BIN="$base/xray/xray" PRISM_VMESS_SERVER_KIND=xray PRISM_VMESS_LARGE_UDP=1 \
  cargo test -p prism-core --test vmess_interop --locked -- --ignored --nocapture
# All five Prism configuration names with common-size UDP. This does not
# certify V2Fly's 8 KiB packet behavior; that probe remains unresolved.
PRISM_VMESS_SERVER_BIN="$base/v2fly/v2ray" PRISM_VMESS_SERVER_KIND=v2fly PRISM_VMESS_LARGE_UDP=0 \
  cargo test -p prism-core --test vmess_interop --locked -- --ignored --nocapture
done
