import importlib.util
import os
from pathlib import Path
import socket
import unittest

spec = importlib.util.spec_from_file_location(
    "vmess_fixture", Path(__file__).resolve().parents[1] / "vmess-fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class VmessListenerTest(unittest.TestCase):
    def test_active_listener_cannot_be_replaced(self):
        with fixture.first_listener(0) as listener:
            address = listener.getsockname()
            with self.assertRaises(OSError):
                fixture.first_listener(address[1])
            with socket.create_connection(address, timeout=2) as client:
                peer, _ = listener.accept()
                with peer:
                    peer.sendall(b"still-owned")
                    self.assertEqual(client.recv(32), b"still-owned")

    @unittest.skipIf(os.name == "nt", "Linux TIME_WAIT rebinding semantics")
    def test_sequential_listener_rebinds_after_active_close(self):
        with fixture.first_listener(0) as listener:
            address = listener.getsockname()
            with socket.create_connection(address, timeout=2) as client:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(2)
                    peer.shutdown(socket.SHUT_WR)
                    self.assertEqual(client.recv(1), b"")
                    client.shutdown(socket.SHUT_WR)
                    self.assertEqual(peer.recv(1), b"")
        # No sleep: the accepted socket is still in TIME_WAIT here.
        with fixture.first_listener(address[1]) as replacement:
            self.assertEqual(replacement.getsockname(), address)


if __name__ == "__main__":
    unittest.main()
