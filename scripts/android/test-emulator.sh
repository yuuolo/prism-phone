#!/usr/bin/env bash
set -euo pipefail
mkdir -p emulator-results
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
