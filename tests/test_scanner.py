import unittest

from scapy.all import ICMP, IP, TCP

from vtknet.core.models import PortState
from vtknet.modules.scanner import ScanType, classify_tcp_reply, tcp_scan_packets


def reply(flags: str, port: int = 443) -> IP:
    return IP(src="10.0.0.5") / TCP(sport=port, dport=55555, flags=flags)


class BuilderTest(unittest.TestCase):
    def test_syn_probe_count_ports_and_flags(self):
        pkts = tcp_scan_packets("10.0.0.5", [80, 443], ScanType.SYN)
        self.assertEqual(len(pkts), 2)
        self.assertEqual([p[TCP].dport for p in pkts], [80, 443])
        self.assertEqual(str(pkts[0][TCP].flags), "S")
        self.assertEqual(pkts[0][IP].dst, "10.0.0.5")

    def test_xmas_flags(self):
        (pkt,) = tcp_scan_packets("10.0.0.5", [80], ScanType.XMAS)
        self.assertEqual(str(pkt[TCP].flags), "FPU")

    def test_null_scan_has_no_flags(self):
        (pkt,) = tcp_scan_packets("10.0.0.5", [80], ScanType.NULL)
        self.assertEqual(str(pkt[TCP].flags), "")


class ClassifyTest(unittest.TestCase):
    def test_syn_open(self):
        self.assertEqual(classify_tcp_reply(ScanType.SYN, reply("SA")), PortState.OPEN)

    def test_syn_closed(self):
        self.assertEqual(classify_tcp_reply(ScanType.SYN, reply("RA")), PortState.CLOSED)

    def test_no_reply_is_filtered(self):
        self.assertEqual(classify_tcp_reply(ScanType.SYN, None), PortState.FILTERED)

    def test_icmp_reply_is_filtered(self):
        self.assertEqual(
            classify_tcp_reply(ScanType.SYN, IP(src="10.0.0.1") / ICMP(type=3, code=1)),
            PortState.FILTERED,
        )

    def test_ack_unfiltered(self):
        self.assertEqual(classify_tcp_reply(ScanType.ACK, reply("R")), PortState.UNFILTERED)

    def test_ack_silence_is_filtered(self):
        self.assertEqual(classify_tcp_reply(ScanType.ACK, None), PortState.FILTERED)


if __name__ == "__main__":
    unittest.main()
