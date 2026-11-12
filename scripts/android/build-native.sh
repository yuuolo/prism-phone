#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Explicit ELF alignment also covers devices configured with 16 KiB pages.
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384"
cargo ndk -t arm64-v8a -t x86_64 --platform 26 -o android/app/src/main/jniLibs build --release -p prism-android --locked
