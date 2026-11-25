#!/usr/bin/env bash
set -euo pipefail
mkdir -p emulator-results
sdk=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
if [ "$sdk" -ge 37 ]; then
  adb shell getconf PAGE_SIZE | tr -d '\r' > emulator-results/page-size.txt
  grep -Fxq '16384' emulator-results/page-size.txt
fi
python3 -u scripts/android/doh-fixture.py --acceptance-domains > emulator-results/doh-fixture.txt 2>&1 &
doh_pid=$!
python3 -u scripts/android/doh-fixture.py --chain-first > emulator-results/doh-chain-first.txt 2>&1 &
chain_pid=$!
vmess_pid=''
trap 'adb reverse --remove tcp:19091 2>/dev/null || true; kill "$doh_pid" "$chain_pid" ${vmess_pid:+"$vmess_pid"} 2>/dev/null || true; wait 2>/dev/null || true' EXIT
source scripts/android/prepare-vmess-servers.sh
vmess_kind=xray
vmess_binary="$base/xray/xray"
vmess_ciphers=auto,aes-128-gcm,chacha20-poly1305
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 37 ]; then
  vmess_kind=v2fly
  vmess_binary="$base/v2fly/v2ray"
  vmess_ciphers="$vmess_ciphers,none,zero"
fi

python3 -u scripts/android/vmess-fixture.py --binary "$vmess_binary" --kind "$vmess_kind" \
  --output-dir emulator-results/vmess-server > emulator-results/vmess-fixture.txt 2>&1 &
vmess_pid=$!
for attempt in {1..40}; do
  grep -q 'VMess mobile fixture ready' emulator-results/vmess-fixture.txt && break
  kill -0 "$vmess_pid" 2>/dev/null || { cat emulator-results/vmess-fixture.txt; exit 1; }
  sleep .25
done
grep -q 'VMess mobile fixture ready' emulator-results/vmess-fixture.txt
adb reverse tcp:19091 tcp:19090
app=$(find "$1" -name '*debug.apk' ! -name '*androidTest*' | head -1)
test=$(find "$1" -name '*androidTest.apk' | head -1)
test -n "$app" && test -n "$test"
adb install -r "$app"
adb install -r "$test"
adb install -r background-tools/routeprobe.apk
if adb shell getprop ro.build.version.sdk | tr -d '\r' | grep -Eq '^(37|[4-9][0-9])$'; then
  adb shell pm grant dev.prism.routeprobe android.permission.ACCESS_LOCAL_NETWORK
fi
adb shell am instrument -w -e vmessCiphers "$vmess_ciphers" dev.prism.android.test/androidx.test.runner.AndroidJUnitRunner | tee emulator-results/instrumentation.txt
adb logcat -d > emulator-results/logcat.txt
adb exec-out screencap -p > emulator-results/screen.png
adb pull /sdcard/Android/data/dev.prism.android/files/screenshots emulator-results/screenshots || true
adb pull /sdcard/Android/data/dev.prism.android/files/vmess-acceptance.json emulator-results/vmess-acceptance.json || true
grep -Eq '^OK \([0-9]+ tests?\)' emulator-results/instrumentation.txt
if [ -n "${2:-}" ]; then
  python3 -u scripts/android/test-background.py \
    --adb "$(command -v adb)" --serial "$(adb get-serialno)" --expected-avd "$2" \
    --seed-apk background-tools/seed.apk --client background-tools/prism-acceptance-client \
    --ui-tool background-tools/prism-ui-snapshot.jar \
    --output emulator-results/background.json --idle-seconds 180 | tee emulator-results/background.txt
  python3 -u scripts/android/test-background.py \
    --adb "$(command -v adb)" --serial "$(adb get-serialno)" --expected-avd "$2" \
    --seed-apk background-tools/seed.apk --client background-tools/prism-acceptance-client \
    --ui-tool background-tools/prism-ui-snapshot.jar --vmess \
    --output emulator-results/vmess-background.json --idle-seconds 180 | tee emulator-results/vmess-background.txt
fi

# Keep TCP through its foreground/idle regressions, then qualify each
# additional transport against a freshly started independent server.
for transport in ws grpc; do
  kill "$vmess_pid"
  wait "$vmess_pid"
  vmess_pid=''
  python3 -u scripts/android/vmess-fixture.py --binary "$vmess_binary" --kind "$vmess_kind" --transport "$transport" \
    --output-dir "emulator-results/vmess-$transport-server" > "emulator-results/vmess-$transport-fixture.txt" 2>&1 &
  vmess_pid=$!
  for attempt in {1..40}; do
    grep -q 'VMess mobile fixture ready' "emulator-results/vmess-$transport-fixture.txt" && break
    kill -0 "$vmess_pid" 2>/dev/null || { cat "emulator-results/vmess-$transport-fixture.txt"; exit 1; }
    sleep .25
  done
  grep -q 'VMess mobile fixture ready' "emulator-results/vmess-$transport-fixture.txt"
  adb install -r "$test"
  adb shell am instrument -w -e class dev.prism.android.VmessTest -e vmessTransport "$transport" \
    -e vmessCiphers "$vmess_ciphers" dev.prism.android.test/androidx.test.runner.AndroidJUnitRunner | tee "emulator-results/vmess-$transport-instrumentation.txt"
  adb logcat -d > "emulator-results/vmess-$transport-logcat.txt"
  adb pull /sdcard/Android/data/dev.prism.android/files/vmess-acceptance.json "emulator-results/vmess-$transport-acceptance.json" || true
  grep -Eq '^OK \(1 test\)' "emulator-results/vmess-$transport-instrumentation.txt"
  if [ -n "${2:-}" ]; then
    python3 -u scripts/android/test-background.py \
      --adb "$(command -v adb)" --serial "$(adb get-serialno)" --expected-avd "$2" \
      --seed-apk background-tools/seed.apk --client background-tools/prism-acceptance-client \
      --ui-tool background-tools/prism-ui-snapshot.jar --vmess --vmess-transport "$transport" \
      --output "emulator-results/vmess-$transport-background.json" --idle-seconds 180 | tee "emulator-results/vmess-$transport-background.txt"
  fi
done
