import unittest

from scapy.all import ICMP, IP, UDP

from vtknet.core.engine import EngineConfig
from vtknet.modules.quicprobe import (
    build_vn_probe_bytes,
    parse_version_negotiation,
    quic_probe,
    quic_probe_packets,
)


def _vn_response(dcid: bytes = b"\x99" * 8, scid: bytes = b"", versions=(0x00000001,)) -> bytes:
    out = bytearray()
    out.append(0xC0)
    out += (0).to_bytes(4, "big")  # VN packets carry version 0
    out.append(len(dcid))
    out += dcid
    out.append(len(scid))
    out += scid
    for v in versions:
        out += v.to_bytes(4, "big")
    return bytes(out)


class BuilderTest(unittest.TestCase):
    def test_probe_bytes_structure(self):
        data = build_vn_probe_bytes(b"\x11" * 8)
        self.assertEqual(data[0], 0xC0)
        self.assertEqual(int.from_bytes(data[1:5], "big"), 0x1A2A3A4A)
        self.assertEqual(data[5], 8)
        self.assertEqual(data[6:14], b"\x11" * 8)
        self.assertEqual(data[14], 0)  # empty SCID

    def test_packet_builder_is_l3_udp(self):
        pkts = quic_probe_packets("203.0.113.9", port=443)
        self.assertEqual(len(pkts), 1)
        self.assertEqual(pkts[0][UDP].dport, 443)
        self.assertEqual(pkts[0][IP].dst, "203.0.113.9")


class ParseTest(unittest.TestCase):
    def test_valid_vn_parsed_with_versions(self):
        info = parse_version_negotiation(_vn_response(versions=(0x00000001, 0xFF00001D)))
        self.assertEqual(info["kind"], "quic.version-negotiation")
        self.assertEqual(info["versions"], ["0x00000001", "0xff00001d"])

    def test_short_header_is_not_vn(self):
        self.assertIsNone(parse_version_negotiation(b"\x40" + b"\x00" * 32))

    def test_real_version_is_not_vn(self):
        pkt = bytearray(_vn_response())
        pkt[1:5] = (0x00000001).to_bytes(4, "big")
        self.assertIsNone(parse_version_negotiation(bytes(pkt)))

    def test_malformed_vn_detected(self):
        info = parse_version_negotiation(b"\xc0\x00\x00\x00\x00\xff")  # truncated CID
        self.assertEqual(info["kind"], "quic.vn-malformed")

    def test_too_small_is_none(self):
        self.assertIsNone(parse_version_negotiation(b"\xc0\x00"))


class _FakeEngine:
    def __init__(self, reply=None) -> None:
        self.cfg = EngineConfig()
        self._reply = reply

    def send1(self, pkt, l2: bool = False):
        return self._reply


class FlowTest(unittest.TestCase):
    def test_vn_reply_produces_finding_with_versions(self):
        rep = IP(src="203.0.113.9") / UDP(sport=443, dport=55555) / _vn_response()
        findings, stats = quic_probe(_FakeEngine(rep), "203.0.113.9", 443)
        self.assertEqual(stats["sent"], 1)
        self.assertEqual(findings[0].kind, "quic.version-negotiation")
        self.assertEqual(findings[0].detail["versions"], ["0x00000001"])
        self.assertEqual(findings[0].evidence[0].kind, "packet_hex")

    def test_no_reply_is_filtered(self):
        findings, _ = quic_probe(_FakeEngine(None), "203.0.113.9", 443)
        self.assertEqual(findings[0].kind, "quic.no-response")
        self.assertEqual(findings[0].state, "filtered")

    def test_icmp_reply_is_unreachable(self):
        rep = IP(src="203.0.113.9") / ICMP(type=3, code=1)
        findings, _ = quic_probe(_FakeEngine(rep), "203.0.113.9", 443)
        self.assertEqual(findings[0].kind, "quic.unreachable")

    def test_non_quic_udp_reply_classified(self):
        rep = IP(src="203.0.113.9") / UDP(sport=443, dport=55555) / b"plain-udp"
        findings, _ = quic_probe(_FakeEngine(rep), "203.0.113.9", 443)
        self.assertEqual(findings[0].kind, "quic.non-quic-reply")

    def test_dry_run_sends_nothing(self):
        eng = _FakeEngine(None)
        eng.cfg = EngineConfig(dry_run=True)
        findings, stats = quic_probe(eng, "203.0.113.9", 443)
        self.assertEqual(findings, [])
        self.assertEqual(stats["sent"], 0)


if __name__ == "__main__":
    unittest.main()
