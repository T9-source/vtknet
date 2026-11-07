import unittest

from vtknet.modules.tlsprobe import (
    build_client_hello_bytes,
    parse_server_hello,
)


def _server_hello_record(version: int = 0x0303, cipher: int = 0xC02F) -> bytes:
    """Hand-built TLS 1.2 ServerHello record (fixed test fixture)."""
    payload = (
        version.to_bytes(2, "big")
        + b"\x11" * 32  # random
        + b"\x00"  # session id length
        + cipher.to_bytes(2, "big")
        + b"\x00"  # compression
        + (0).to_bytes(2, "big")  # extensions length
    )
    hs = b"\x02" + len(payload).to_bytes(3, "big") + payload
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _alert_record() -> bytes:
    return b"\x15\x03\x03\x00\x02\x02\x28"  # fatal handshake_failure


class ClientHelloTest(unittest.TestCase):
    def test_record_prefix_and_determinism(self):
        a = build_client_hello_bytes()
        b = build_client_hello_bytes()
        self.assertTrue(a.startswith(b"\x16\x03\x01"))
        self.assertEqual(a, b)  # default rng seed -> deterministic

    def test_sni_embedded(self):
        hello = build_client_hello_bytes(sni="example.com")
        self.assertIn(b"example.com", hello)

    def test_ciphers_embedded(self):
        hello = build_client_hello_bytes(ciphers=[0x1301])
        self.assertIn((0x1301).to_bytes(2, "big"), hello)


class ParseTest(unittest.TestCase):
    def test_server_hello_parsed(self):
        info = parse_server_hello(_server_hello_record())
        self.assertEqual(info["kind"], "tls.serverhello")
        self.assertEqual(info["version_int"], "0x0303")
        self.assertEqual(info["cipher"], 0xC02F)

    def test_alert_parsed(self):
        info = parse_server_hello(_alert_record())
        self.assertEqual(info["kind"], "tls.alert")
        self.assertEqual(info["description"], 40)


# Probe flow tests moved to test_tls_certs.py (FakeLink + link_factory DI) —
# the live path must NEVER open real sockets from the test suite.


if __name__ == "__main__":
    unittest.main()
