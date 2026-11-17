#!/usr/bin/env bash
set -euo pipefail
mkdir -p emulator-results
python3 -u scripts/android/doh-fixture.py --acceptance-domains > emulator-results/doh-fixture.txt 2>&1 &
doh_pid=$!
python3 -u scripts/android/doh-fixture.py --chain-first > emulator-results/doh-chain-first.txt 2>&1 &
chain_pid=$!
trap 'adb reverse --remove tcp:19091 2>/dev/null || true; kill "$doh_pid" "$chain_pid" 2>/dev/null || true' EXIT
adb reverse tcp:19091 tcp:19090
app=$(find "$1" -name '*debug.apk' ! -name '*androidTest*' | head -1)
test=$(find "$1" -name '*androidTest.apk' | head -1)
test -n "$app" && test -n "$test"
adb install -r "$app"
adb install -r "$test"
adb shell am instrument -w dev.prism.android.test/androidx.test.runner.AndroidJUnitRunner | tee emulator-results/instrumentation.txt
adb logcat -d > emulator-results/logcat.txt
adb exec-out screencap -p > emulator-results/screen.png
adb pull /sdcard/Android/data/dev.prism.android/files/screenshots emulator-results/screenshots || true
grep -Eq '^OK \([0-9]+ tests?\)' emulator-results/instrumentation.txt
if [ -n "${2:-}" ]; then
  python3 -u scripts/android/test-background.py \
    --adb "$(command -v adb)" --serial "$(adb get-serialno)" --expected-avd "$2" \
    --seed-apk background-tools/seed.apk --client background-tools/prism-acceptance-client \
    --output emulator-results/background.json --idle-seconds 180 | tee emulator-results/background.txt
fi
