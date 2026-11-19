"""Loopback-only test SOCKS relay: fixed public DoH and opt-in DoT endpoint.

No TLS termination, test CA, proxy credentials, or DNS response substitution.
The emulator's 10.0.2.2 host alias reaches this listener after LAN permission.
--chain-first instead permits only the fixed loopback second SOCKS listener.
"""
import argparse
import concurrent.futures
import ipaddress
import itertools
import select
import socket
import threading


connection_ids = itertools.count(1)


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return bytes(data)


def serve(client, chain_first=False, acceptance_domains=False):
    connection_id = next(connection_ids)
    def log(message):
        print(f"relay {connection_id}: {message}", flush=True)
    with client:
        client.settimeout(12)
        log("client connected")
        try:
            if read_exact(client, 1) != b"\x05":
                return
            methods = read_exact(client, read_exact(client, 1)[0])
            if 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")
            version, command, reserved, kind = read_exact(client, 4)
            if kind == 1:
                host = str(ipaddress.IPv4Address(read_exact(client, 4)))
            elif kind == 4:
                host = str(ipaddress.IPv6Address(read_exact(client, 16)))
            elif kind == 3:
                host = read_exact(client, read_exact(client, 1)[0]).decode("ascii")
            else:
                return
            port = int.from_bytes(read_exact(client, 2), "big")
            # Acceptance may also test strict DNS-over-TLS at the same fixed
            # public address. Never forward arbitrary destinations or ports.
            dot_port = 853 if acceptance_domains and port == 853 else 443
            allowed = ("127.0.0.1", 19090) if chain_first else ("1.1.1.1", dot_port)
            fixed_domain = acceptance_domains and not chain_first and host in ("one.one.one.one", "cloudflare-dns.com") and port == 443
            if (version, command, reserved) != (5, 1, 0) or not ((host, port) == allowed or fixed_domain):
                log("target rejected by fixed allowlist")
                client.sendall(b"\x05\x02\x00\x01" + bytes(6))
                return
            # Optional two-name acceptance aliases use the same fixed public
            # TLS service. Never resolve/forward an arbitrary requested host.
            destination = ("1.1.1.1",443) if fixed_domain else (host,port)
            with socket.create_connection(destination, timeout=10) as remote:
                client.sendall(b"\x05\x00\x00\x01" + bytes(6))
                # Only fixed allowlisted labels; never log arbitrary destinations.
                label = "fixed second SOCKS hop" if chain_first else (host if fixed_domain else "fixed DoT upstream" if port == 853 else "fixed DoH upstream")
                log("forwarding to " + label)
                remote.settimeout(12)
                uploaded = downloaded = 0
                while True:
                    ready, _, _ = select.select([client, remote], [], [], 12)
                    if not ready:
                        log(f"idle timeout; up={uploaded} down={downloaded}")
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            direction = "client" if source is client else "upstream"
                            log(f"EOF from {direction}; up={uploaded} down={downloaded}")
                            return
                        if source is client:
                            uploaded += len(data)
                        else:
                            downloaded += len(data)
                        (remote if source is client else client).sendall(data)
        except (OSError, EOFError, UnicodeError) as error:
            # Failure remains visible to the app; never synthesize a DNS success.
            log("failure: " + type(error).__name__)
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int)
    parser.add_argument("--chain-first", action="store_true", help="Only forward to the fixed loopback second hop; never arbitrary targets")
    parser.add_argument("--acceptance-domains", action="store_true", help="Permit the two fixed public TLS names for cold native DNS acceptance")
    args = parser.parse_args()
    port = args.port if args.port is not None else (19092 if args.chain_first else 19090)
    if not 1024 <= port <= 65535:
        parser.error("port must be in 1024..65535")
    slots = threading.BoundedSemaphore(8)
    def bounded_serve(client):
        try:
            serve(client, args.chain_first, args.acceptance_domains)
        finally:
            slots.release()
    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(8)
        print("DoH test relay ready on loopback", flush=True)
        while True:
            client, _ = listener.accept()
            if slots.acquire(blocking=False):
                pool.submit(bounded_serve, client)
            else:
                print("relay capacity exhausted", flush=True)
                client.close()


if __name__ == "__main__":
    main()
