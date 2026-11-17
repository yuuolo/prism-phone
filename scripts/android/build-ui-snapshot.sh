#!/usr/bin/env bash
set -euo pipefail
# External one-shot shell tool; no code or hidden API usage enters the APK.
out="${1:-background-tools}"
mkdir -p "$out/classes"
sdk="$ANDROID_HOME/platforms/android-37.0/android.jar"
javac --release 8 -cp "$sdk" -d "$out/classes" scripts/android/tools/PrismUiSnapshot.java
java -cp "$ANDROID_HOME/build-tools/37.0.0/lib/d8.jar" com.android.tools.r8.D8 \
  --lib "$sdk" --min-api 26 --output "$out/prism-ui-snapshot.jar" "$out/classes/PrismUiSnapshot.class"
