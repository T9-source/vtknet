import os
import tempfile
import unittest

from scapy.all import IP, TCP, UDP, Ether, wrpcap

from vtknet.core.inspect import decode_bytes, parse_evidence, pcap_summary

LAB = "203.0.113.9"


class ParseEvidenceTest(unittest.TestCase):
    def test_plain_hex(self):
        self.assertEqual(parse_evidence("deadbeef"), b"\xde\xad\xbe\xef")

    def test_colons_spaces_and_0x(self):
        self.assertEqual(parse_evidence("de ad:be ef"), b"\xde\xad\xbe\xef")
        self.assertEqual(parse_evidence("0xDEADBEEF"), b"\xde\xad\xbe\xef")
        self.assertEqual(parse_evidence("de:ad:be:ef"), b"\xde\xad\xbe\xef")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            parse_evidence("   ")

    def test_non_hex_rejected(self):
        with self.assertRaises(ValueError):
            parse_evidence("hello world!")


class DecodeBytesTest(unittest.TestCase):
    def test_ether_framed_bytes_decode(self):
        data = bytes(Ether() / IP(dst=LAB) / TCP(dport=443, flags="S"))
        pkt = decode_bytes(data)
        self.assertEqual([l.__name__ for l in pkt.layers()], ["Ether", "IP", "TCP"])

    def test_raw_ip_bytes_fall_back_to_ip(self):
        data = bytes(IP(dst=LAB) / TCP(dport=443, flags="S"))  # no Ether header
        pkt = decode_bytes(data)
        self.assertEqual([l.__name__ for l in pkt.layers()], ["IP", "TCP"])

    def test_raw_ipv6_bytes_fall_back_to_ipv6(self):
        data = bytes(IP(dst=LAB) / TCP(dport=443, flags="S"))
        ipv6_like = b"\x60" + data[1:]  # fake version nibble 6
        pkt = decode_bytes(ipv6_like)
        self.assertEqual(pkt.layers()[0].__name__, "IPv6")


class PcapSummaryTest(unittest.TestCase):
    def test_streaming_summary(self):
        pkts = [
            Ether() / IP(src="192.0.2.5", dst=LAB) / TCP(sport=1111, dport=443, flags="S"),
            Ether() / IP(src=LAB, dst="192.0.2.5") / TCP(sport=443, dport=1111, flags="SA"),
            Ether() / IP(src="192.0.2.5", dst="192.0.2.1") / UDP(sport=5353, dport=53),
        ]
        pkts[0].time = 1_000_000_000
        pkts[1].time = 1_000_000_005
        pkts[2].time = 1_000_000_010
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcap")
            wrpcap(path, pkts)
            s = pcap_summary(path)
        self.assertEqual(s["packets"], 3)
        self.assertEqual(s["duration_s"], 10.0)
        self.assertTrue(s["started"])
        self.assertIn("TCP", s["layers_seen"])
        talkers = dict(s["top_talkers"])
        self.assertIn(f"192.0.2.5 -> {LAB}", talkers)
        convs = [c for c, _ in s["top_conversations"]]
        self.assertTrue(any(c.startswith("TCP 192.0.2.5:1111 >") for c in convs))
        self.assertTrue(any(c.startswith("UDP 192.0.2.5:5353 >") for c in convs))

    def test_empty_pcap(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "empty.pcap")
            wrpcap(path, [])
            s = pcap_summary(path)
        self.assertEqual(s["packets"], 0)
        self.assertEqual(s["duration_s"], 0.0)


if __name__ == "__main__":
    unittest.main()
