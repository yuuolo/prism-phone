"""Uninstrumented VPN / deep-idle acceptance on owned disposable emulators.

The seed instrumentation exits and is force-stopped before normal UI startup.
The separate ELF client uses ordinary TUN-routed sockets and verified TLS.
No root, battery whitelist, keep-alive traffic, or management API is added.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--expected-avd", required=True, choices=["PrismPhoneCI", "PrismPhoneApi26", "PrismAdvancedCI"])
    parser.add_argument("--seed-apk", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--ui-tool", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--idle-seconds", type=int, default=180)
    args = parser.parse_args()
    if not re.fullmatch(r"emulator-[0-9]+", args.serial) or not 20 <= args.idle_seconds <= 3600:
        parser.error("Use an owned emulator serial and an idle duration in 20..3600")

    def adb(*command, check=True, timeout=25):
        result = subprocess.run([args.adb, "-s", args.serial, *command], capture_output=True, timeout=timeout)
        text = result.stdout.decode("utf-8", "replace").strip()
        if check and result.returncode:
            raise RuntimeError(f"adb {command[0]} failed: " + result.stderr.decode("utf-8", "replace")[:300])
        return text

    def shell(*command, **kwargs):
        return adb("shell", *command, **kwargs)

    def wait_for(description, action, timeout=15):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = action()
            if value:
                return value
            time.sleep(.2)
        raise RuntimeError("Timed out: " + description)

    def pid():
        return shell("pidof", "dev.prism.android", check=False)

    def vpn_network():
        # Public dumpsys works without netlink/sysfs privileges on both images.
        for line in shell("dumpsys", "connectivity").splitlines():
            if "NetworkAgentInfo{" in line and "InterfaceName: tun" in line and "172.19.0.1" in line:
                net = re.search(r"network\{([0-9]+)\}", line)
                interface = re.search(r"InterfaceName: (tun[0-9]+)", line)
                if net and interface:
                    return {"networkId": net[1], "interface": interface[1]}
        return None

    def foreground_service():
        return "isForeground=true" in shell("dumpsys", "activity", "services", "dev.prism.android")

    def idle_state():
        raw = shell("dumpsys", "deviceidle")
        state = re.search(r"\bmState=([A-Z_]+)", raw)
        return {"forced": "mForceIdle=true" in raw, "state": state[1] if state else "unknown"}

    def memory_kb():
        raw = shell("dumpsys", "meminfo", "dev.prism.android")
        total = re.search(r"TOTAL PSS:\s*([0-9]+)", raw) or re.search(r"^\s*TOTAL\s+([0-9]+)", raw, re.M)
        return int(total[1]) if total else None

    def probe(phase):
        raw = shell("/data/local/tmp/prism-acceptance-client", phase, timeout=25)
        result = json.loads(raw)
        if result.get("clientVersion")!=2 or result.get("phase")!=phase or not result.get("ok") or result.get("tls") != "verified" or result.get("systemDns") != "vpn-fake-ip":
            raise RuntimeError("Independent TUN/TLS client did not pass")
        return result

    def ui():
        # A live dashboard changes every second. The platform dump command's
        # one-second idle requirement is inappropriate for this screen.
        last_dump = ""
        for _ in range(3):
            dumped = subprocess.run([args.adb,"-s",args.serial,"shell","env","CLASSPATH=/data/local/tmp/prism-ui-snapshot.jar","app_process","/system/bin","PrismUiSnapshot"],capture_output=True,timeout=10)
            last_dump = dumped.stderr.decode("utf-8","replace").strip()
            try:
                if dumped.returncode:
                    raise ET.ParseError("snapshot process failed")
                return ET.fromstring(dumped.stdout)
            except ET.ParseError:
                time.sleep(.5)
        raise RuntimeError("No current UI hierarchy: " + last_dump[:350])

    def click_button(text):
        for node in ui().iter("node"):
            if node.get("text") == text and node.get("package") == "dev.prism.android" and node.get("class") == "android.widget.Button" and node.get("enabled") == "true":
                points = list(map(int, re.findall(r"[0-9]+", node.get("bounds", ""))))
                if len(points) == 4:
                    shell("input", "tap", str((points[0] + points[2]) // 2), str((points[1] + points[3]) // 2))
                    return
        raise RuntimeError("Expected current app button was not present")

    avd = adb("emu", "avd", "name").splitlines()[0]
    if avd != args.expected_avd:
        raise RuntimeError("AVD identity differs; refusing to change fixture data")
    package = shell("dumpsys", "package", "dev.prism.android")
    if not re.search(r"^\s*flags=\[[^\]\r\n]*\bDEBUGGABLE\b", package, re.M):
        raise RuntimeError("Only a debuggable fixture package may be reset")
    if idle_state()["forced"] or "UPDATES STOPPED" in shell("dumpsys", "battery"):
        raise RuntimeError("A pre-existing power override must be restored by its owner first")
    original_awake = "mWakefulness=Awake" in shell("dumpsys", "power")
    for path in [args.seed_apk, args.client, args.ui_tool]:
        if not Path(path).is_file():
            raise RuntimeError("Missing acceptance input")

    report = {"serial": args.serial, "avd": avd, "idleSeconds": args.idle_seconds, "ok": False}
    phase = "setup"
    power_changed = False
    succeeded = False
    try:
        adb("install", "-r", args.seed_apk)
        shell("am", "force-stop", "dev.prism.android")
        seed = shell("am", "instrument", "-w", "dev.prism.android.test/dev.prism.android.BackgroundSeedInstrumentation")
        if "backgroundFixture=seeded-cold-dns-v1" not in seed:
            raise RuntimeError("Seed runner did not prepare the disposable fixture")
        shell("am", "force-stop", "dev.prism.android")
        wait_for("seed process exits", lambda: not pid())
        shell("appops", "set", "dev.prism.android", "ACTIVATE_VPN", "allow")
        if int(shell("getprop", "ro.build.version.sdk")) >= 37:
            shell("pm", "grant", "dev.prism.android", "android.permission.ACCESS_LOCAL_NETWORK")
        adb("push", args.client, "/data/local/tmp/prism-acceptance-client")
        adb("push", args.ui_tool, "/data/local/tmp/prism-ui-snapshot.jar")
        shell("chmod", "755", "/data/local/tmp/prism-acceptance-client")
        shell("input", "keyevent", "224")
        shell("wm", "dismiss-keyguard", check=False)
        shell("am", "start", "-n", "dev.prism.android/.MainActivity", "-f", "0x10008000")
        time.sleep(1)
        phase = "ui-connect"
        click_button("连接")
        phase = "ui-connected"
        wait_for("connected app UI",lambda:any(n.get("text")=="已连接" for n in ui().iter("node")))
        network = wait_for("normal UI VPN connection", vpn_network)
        app_pid = pid()
        if not app_pid or not foreground_service():
            raise RuntimeError("Normal VPN foreground service not running")
        report["before"] = {"pid": app_pid, "vpn": network, "pssKb": memory_kb(), "probe": probe("before")}
        if re.search(r"^(user|system|system-excidle),dev\.prism\.android,", shell("dumpsys", "deviceidle", "whitelist"), re.M):
            raise RuntimeError("Fixture has a battery whitelist exception")

        phase = "idle"
        shell("input", "keyevent", "3")
        shell("input", "keyevent", "223")
        shell("dumpsys", "battery", "unplug")
        power_changed = True
        shell("dumpsys", "deviceidle", "force-idle")
        wait_for("forced deep idle", lambda: idle_state() == {"forced": True, "state": "IDLE"})
        begin = time.monotonic()
        while time.monotonic() - begin < args.idle_seconds:
            time.sleep(min(30, args.idle_seconds - (time.monotonic() - begin)))
            # Host heartbeat only: do not touch the app or send keep-alive traffic.
            print(json.dumps({"phase": "idle", "elapsedSeconds": int(time.monotonic() - begin)}), flush=True)
        if pid() != app_pid or vpn_network() != network or not foreground_service():
            raise RuntimeError("VPN process, network identity or foreground service changed in idle")
        if idle_state() != {"forced": True, "state": "IDLE"}:
            raise RuntimeError("Deep idle did not persist for the observation")
        report["idle"] = {"state": idle_state(), "pssKb": memory_kb(), "probe": probe("idle")}
        if idle_state() != {"forced": True, "state": "IDLE"}:
            raise RuntimeError("Client probe exited deep idle")

        phase = "resume"
        shell("dumpsys", "deviceidle", "unforce")
        shell("dumpsys", "battery", "reset")
        shell("input", "keyevent", "224")
        shell("wm", "dismiss-keyguard", check=False)
        wait_for("normal power policy restored",lambda:not idle_state()["forced"] and "UPDATES STOPPED" not in shell("dumpsys","battery"))
        power_changed = False
        report["resumed"] = {"pid": pid(), "vpn": vpn_network(), "probe": probe("resumed")}
        if pid() != app_pid or vpn_network() != network:
            raise RuntimeError("VPN restarted on wake")
        shell("am", "start", "-n", "dev.prism.android/.MainActivity", "-f", "0x10008000")
        time.sleep(1)
        phase = "ui-disconnect"
        click_button("断开")
        wait_for("user disconnect releases VPN", lambda: vpn_network() is None and not foreground_service())
        time.sleep(4)
        if vpn_network() is not None or foreground_service():
            raise RuntimeError("VPN resurrected after user disconnect")
        report["userDisconnect"] = "stayed-stopped"
        negative=subprocess.run([args.adb,"-s",args.serial,"shell","/data/local/tmp/prism-acceptance-client"],capture_output=True,timeout=25)
        refusal=negative.stderr.decode("utf-8","replace")
        if negative.returncode==0 or not any(reason in refusal for reason in ["system DNS phase","client TCP bypassed the VPN interface","system DNS did not pass through the VPN fake-IP resolver","target DNS bypassed VPN fake-IP"]):
            raise RuntimeError("Client did not reject the disconnected control case")
        report["disconnectedControl"]="rejected"
        report["ok"] = True
        succeeded = True
    except Exception as error:
        report["failure"] = {"phase": phase, "type": type(error).__name__, "message": str(error)[:500]}
        # Capture before force-stop/power cleanup destroys the failing state.
        # This script already restricts all operations to disposable owned AVDs.
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        for label, command in [("logcat", ["logcat", "-d", "-t", "2000"]),
                               ("connectivity", ["shell", "dumpsys", "connectivity"]),
                               ("activity", ["shell", "dumpsys", "activity", "top"])]:
            try:
                captured = adb(*command, check=False, timeout=10)
                output.with_name(output.stem + "-failure-" + label + ".txt").write_text(captured, encoding="utf-8")
            except Exception as capture_error:
                report.setdefault("diagnosticErrors", []).append(type(capture_error).__name__)
    finally:
        if power_changed:
            shell("dumpsys", "deviceidle", "unforce", check=False)
            shell("dumpsys", "battery", "reset", check=False)
        shell("input", "keyevent", "224", check=False)
        shell("wm", "dismiss-keyguard", check=False)
        shell("am", "force-stop", "dev.prism.android", check=False)
        if not original_awake:
            shell("input", "keyevent", "223", check=False)
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report), flush=True)
    if not succeeded:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
