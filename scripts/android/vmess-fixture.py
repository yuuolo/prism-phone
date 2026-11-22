"""Owned-emulator VMess fixture: loopback VMess, fixed SOCKS hop and UDP echo.

The VMess server forwards TCP through doh-fixture.py's fixed endpoint allowlist.
Only UDP to this fixture's own loopback echo is sent through freedom. No server
binary, CA override or arbitrary forwarding service is bundled with the app.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import threading
import time

ID = "0b6a0b4e-1111-4222-8333-444455556666"
VMESS_PORT, ECHO_PORT, FIRST_PORT = 19094, 19095, 19097


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--kind", required=True, choices=["xray", "v2fly"])
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
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
            "streamSettings": {"network": "tcp", "security": "none"}}],
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
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo, socket.socket() as first:
        echo.bind(("127.0.0.1", ECHO_PORT))
        echo.settimeout(.5)
        first.bind(("127.0.0.1", FIRST_PORT))
        first.listen(8)
        first.settimeout(.5)
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
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
                    print("VMess mobile fixture ready (loopback only)", flush=True)
                    while not stop.wait(.5):
                        if child.poll() is not None:
                            raise RuntimeError("VMess fixture server stopped")
                finally:
                    stop.set()
                    child.terminate()
                    child.wait(timeout=5)


if __name__ == "__main__":
    main()
