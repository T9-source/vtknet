import unittest

from scapy.all import IP, TCP, Raw

from vtknet.core.engine import EngineConfig
from vtknet.modules.tlsprobe import (
    build_client_hello_bytes,
    parse_server_hello,
    tls_probe,
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


class _FakeEngine:
    """Duck-typed Engine: SYN gets a canned SYN-ACK; probe gets a canned ServerHello."""

    def __init__(self) -> None:
        self.cfg = EngineConfig(dry_run=False)
        self.reply = IP(src="203.0.113.9", dst="192.0.2.5") / TCP(
            sport=443, dport=55555, flags="PA"
        ) / Raw(_server_hello_record())

    def send1(self, pkt, l2: bool = False):
        if pkt.haslayer(TCP) and int(pkt[TCP].flags) == 0x02:
            return IP(src="203.0.113.9", dst=pkt[IP].src) / TCP(
                sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="SA", seq=100
            )
        return None

    def send(self, pkts, l2: bool = False) -> None:
        return None

    def send_recv(self, pkts, l2: bool = False):
        probe = pkts[0]
        self.reply[TCP].dport = probe[TCP].sport
        return [(probe, self.reply)], []


class ProbeFlowTest(unittest.TestCase):
    def test_full_probe_flow_returns_serverhello_finding(self):
        findings, stats = tls_probe(_FakeEngine(), "203.0.113.9", port=443, sni="example.com")
        self.assertEqual(stats["sent"], 3)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, "tls.serverhello")
        self.assertEqual(f.state, "open")
        self.assertEqual(f.detail["cipher"], 0xC02F)
        self.assertEqual(f.detail["version_int"], "0x0303")
        self.assertEqual(f.evidence[0].kind, "packet_hex")


if __name__ == "__main__":
    unittest.main()
