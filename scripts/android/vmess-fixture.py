"""Owned-emulator VMess fixture: loopback VMess, fixed SOCKS hop and UDP echo.

The VMess server forwards TCP through doh-fixture.py's fixed endpoint allowlist.
Only UDP to this fixture's own loopback echo is sent through freedom. No server
binary, CA override or arbitrary forwarding service is bundled with the app.
"""
import argparse
import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import subprocess
import threading
import time

ID = "0b6a0b4e-1111-4222-8333-444455556666"
VMESS_PORT, ECHO_PORT, FIRST_PORT = 19094, 19095, 19097
CAMOUFLAGE_PORT = 19098
REALITY_NAME, REALITY_SID = "reality.fixture.test", "0123456789abcdef"


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError()
        data.extend(part)
    return bytes(data)


def first_hop(client):
    with client:
        client.settimeout(8)
        try:
            version, count = exact(client, 2)
            if version != 5 or not 1 <= count <= 8 or 0 not in exact(client, count):
                return
            client.sendall(b"\x05\x00")
            version, command, reserved, kind = exact(client, 4)
            if (version, command, reserved, kind) != (5, 1, 0, 1):
                return
            host, port = socket.inet_ntoa(exact(client, 4)), int.from_bytes(exact(client, 2), "big")
            if host != "127.0.0.1" or port != VMESS_PORT:
                client.sendall(b"\x05\x02\x00\x01" + bytes(6))
                return
            with socket.create_connection(("127.0.0.1", VMESS_PORT), timeout=8) as remote:
                client.sendall(b"\x05\x00\x00\x01" + bytes(6))
                while True:
                    ready, _, _ = select.select([client, remote], [], [], 30)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (remote if source is client else client).sendall(data)
        except (OSError, EOFError):
            return


def first_listener(port=FIRST_PORT):
    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Sequential TCP -> WS runs reuse this loopback port. Linux keeps
        # accepted connections in TIME_WAIT after the old listener exits.
        # Do not enable Windows' different, overlapping-bind semantics.
        if os.name != "nt":
            first.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        first.bind(("127.0.0.1", port))
        first.listen(8)
        first.settimeout(.5)
        return first
    except BaseException:
        first.close()
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--kind", required=True, choices=["xray", "v2fly"])
    parser.add_argument("--transport", choices=["tcp", "ws", "grpc"], default="tcp")
    parser.add_argument("--protocol", choices=["vmess", "reality", "vision"], default="vmess")
    parser.add_argument("--camouflage-dir")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    reality = args.protocol != "vmess"
    if reality and (args.kind != "xray" or args.transport != "tcp" or not args.camouflage_dir):
        parser.error("Reality/Vision requires Xray, TCP and --camouflage-dir")
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    for event in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(event, lambda *_: stop.set())
    freedom = {"tag": "echo", "protocol": "freedom"}
    if args.kind == "xray":
        freedom["settings"] = {"finalRules": [{"action": "allow", "network": "udp",
            "ip": ["127.0.0.1"], "port": str(ECHO_PORT)}]}
    config = {
        "log": {"loglevel": "info"},
        "inbounds": [{"listen": "127.0.0.1", "port": VMESS_PORT, "protocol": "vmess",
            "settings": {"clients": [{"id": ID, "alterId": 0}]},
            "streamSettings": {"network": args.transport, "security": "none",
                **({"wsSettings": {"path": "/prism-vmess-mobile"}} if args.transport == "ws" else
                   {"grpcSettings": {"serviceName": "PrismVmessMobile"}} if args.transport == "grpc" else {})}}],
        "outbounds": [
            {"tag": "tls-relay", "protocol": "socks", "settings": {
                "servers": [{"address": "127.0.0.1", "port": 19090}]}},
            freedom, {"tag": "blocked", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "network": "udp", "ip": ["127.0.0.1"],
                "port": str(ECHO_PORT), "outboundTag": "echo"},
            {"type": "field", "network": "udp", "outboundTag": "blocked"},
            {"type": "field", "network": "tcp", "outboundTag": "tls-relay"}]},
    }
    config_path = output / "server.json"
    tls_context = None
    if reality:
        cert_dir = Path(args.camouflage_dir).resolve(strict=True)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.set_alpn_protocols(["h2", "http/1.1"])
        tls_context.load_cert_chain(cert_dir / "camouflage-cert.pem", cert_dir / "camouflage-key.pem")
        key_result = subprocess.run([str(binary), "x25519"], capture_output=True, text=True, check=True,
            creationflags=0x08000000 if os.name == "nt" else 0)
        fields = dict(line.split(":", 1) for line in key_result.stdout.splitlines() if ":" in line)
        private = fields.get("PrivateKey", "").strip()
        public = (fields.get("Password (PublicKey)") or fields.get("Password") or fields.get("PublicKey") or "").strip()
        if not private or not public:
            raise RuntimeError("Xray key generation did not provide expected fields")
        user = {"id": ID}
        if args.protocol == "vision":
            user["flow"] = "xtls-rprx-vision"
        config["inbounds"] = [{"listen": "127.0.0.1", "port": VMESS_PORT, "protocol": "vless",
            "settings": {"clients": [user], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "target": f"127.0.0.1:{CAMOUFLAGE_PORT}", "serverNames": [REALITY_NAME],
                "privateKey": private, "shortIds": [REALITY_SID]}}}]
        (output / "public.json").write_text(json.dumps({"protocol": args.protocol, "uuid": ID,
            "publicKey": public, "shortId": REALITY_SID, "serverName": REALITY_NAME}), encoding="utf-8")
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    with contextlib.ExitStack() as owned:
        echo = owned.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        first = owned.enter_context(first_listener())
        camouflage = owned.enter_context(first_listener(CAMOUFLAGE_PORT)) if reality else None
        echo.bind(("127.0.0.1", ECHO_PORT))
        echo.settimeout(.5)
        def udp_echo():
            while not stop.is_set():
                try:
                    data, peer = echo.recvfrom(65535)
                    echo.sendto(data, peer)
                except socket.timeout:
                    continue
                except OSError:
                    return
        slots = threading.BoundedSemaphore(8)
        def bounded(client):
            try:
                first_hop(client)
            finally:
                slots.release()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16 if reality else 8) as pool:
            camouflage_slots = threading.BoundedSemaphore(8)
            def camouflage_client(client):
                try:
                    with client:
                        client.settimeout(5)
                        with tls_context.wrap_socket(client, server_side=True) as tls:
                            tls.recv(1)
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    camouflage_slots.release()
            def camouflage_accepts():
                while not stop.is_set():
                    try:
                        client, _ = camouflage.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    if camouflage_slots.acquire(blocking=False):
                        pool.submit(camouflage_client, client)
                    else:
                        client.close()
            if camouflage:
                threading.Thread(target=camouflage_accepts, daemon=True).start()
            def accepts():
                while not stop.is_set():
                    try:
                        client, _ = first.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    if slots.acquire(blocking=False):
                        pool.submit(bounded, client)
                    else:
                        client.close()
            threading.Thread(target=udp_echo, daemon=True).start()
            threading.Thread(target=accepts, daemon=True).start()
            with (output / "server.log").open("wb") as log:
                child = subprocess.Popen([str(binary), "run", "-c" if args.kind == "v2fly" else "-config",
                    str(config_path)], stdout=log, stderr=subprocess.STDOUT,
                    creationflags=0x08000000 if os.name == "nt" else 0)
                (output / "processes.json").write_text(json.dumps({"parent": os.getpid(),
                    "server": child.pid, "kind": args.kind, "config": str(config_path)}), encoding="utf-8")
                try:
                    deadline = time.monotonic() + 8
                    while True:
                        if child.poll() is not None:
                            raise RuntimeError("VMess fixture server exited; inspect server.log")
                        try:
                            with socket.create_connection(("127.0.0.1", VMESS_PORT), timeout=.3):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise RuntimeError("VMess fixture server did not listen")
                            time.sleep(.05)
                    label = "Reality" if reality else "VMess"
                    print(f"{label} mobile fixture ready (loopback only)", flush=True)
                    while not stop.wait(.5):
                        if child.poll() is not None:
                            raise RuntimeError("VMess fixture server stopped")
                finally:
                    stop.set()
                    child.terminate()
                    child.wait(timeout=5)


if __name__ == "__main__":
    main()
