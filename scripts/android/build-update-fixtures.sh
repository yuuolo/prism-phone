#!/usr/bin/env bash
set -euo pipefail
tools="$ANDROID_HOME/build-tools/37.0.0"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
assets=android/app/src/androidTest/assets
mkdir -p "$assets"
cat > "$scratch/AndroidManifest.xml" <<'XML'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="dev.prism.android" android:versionCode="3" android:versionName="0.2.1-test">
<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="37" />
<application android:label="Update verification fixture" android:hasCode="false" />
</manifest>
XML
"$tools/aapt2" link --manifest "$scratch/AndroidManifest.xml" -I "$ANDROID_HOME/platforms/android-37.0/android.jar" -o "$scratch/unsigned.apk"
# These are disposable test keys, never the production Android signing key.
debug_store=$(bash android/gradlew -p android -q signingReport --console plain | awk '/^[[:space:]]*Store: / && !printed {sub(/^[[:space:]]*Store: /, ""); print; printed=1}')
test -f "$debug_store"
"$tools/apksigner" sign --ks "$debug_store" --ks-key-alias androiddebugkey --ks-pass pass:android --out "$assets/future-update.apk" "$scratch/unsigned.apk"
keytool -genkeypair -keystore "$scratch/wrong.jks" -storetype JKS -alias fixture -keyalg RSA -keysize 2048 -validity 2 -dname 'CN=Disposable fixture' -storepass android -keypass android >/dev/null 2>&1
"$tools/apksigner" sign --ks "$scratch/wrong.jks" --ks-key-alias fixture --ks-pass pass:android --out "$assets/wrong-signer.apk" "$scratch/unsigned.apk"
