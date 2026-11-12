"""Loopback-only test SOCKS relay: permit only the app's fixed public DoH IP.

No TLS termination, test CA, proxy credentials, or DNS response substitution.
An adb reverse mapping reaches this host loopback listener from the test guest.
"""
import argparse
import concurrent.futures
import ipaddress
import select
import socket


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return bytes(data)


def serve(client):
    with client:
        client.settimeout(12)
        print("test SOCKS client connected", flush=True)
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
            if (version, command, reserved, host, port) != (5, 1, 0, "1.1.1.1", 443):
                client.sendall(b"\x05\x02\x00\x01" + bytes(6))
                return
            with socket.create_connection((host, port), timeout=10) as remote:
                client.sendall(b"\x05\x00\x00\x01" + bytes(6))
                print("forwarding TLS to fixed DoH upstream", flush=True)
                remote.settimeout(12)
                while True:
                    ready, _, _ = select.select([client, remote], [], [], 12)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (remote if source is client else client).sendall(data)
        except (OSError, EOFError, UnicodeError) as error:
            # Failure remains visible to the app; never synthesize a DNS success.
            print("relay failure: " + type(error).__name__, flush=True)
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=19090)
    args = parser.parse_args()
    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.port))
        listener.listen(8)
        print("DoH test relay ready on loopback", flush=True)
        while True:
            client, _ = listener.accept()
            pool.submit(serve, client)


if __name__ == "__main__":
    main()
