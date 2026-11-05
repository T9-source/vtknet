import os
import tempfile
import unittest

from scapy.all import ARP, ICMP, IP, TCP, Ether, rdpcap, wrpcap

from vtknet.core.capture import Capture, CaptureConfig, match_replies
from vtknet.core.engine import Engine, EngineConfig
from vtknet.modules import synthetic


def _syn_probe() -> IP:
    return IP(src="192.0.2.5", dst="203.0.113.9") / TCP(sport=40000, dport=443, flags="S")


def _synack_reply() -> IP:
    return IP(src="203.0.113.9", dst="192.0.2.5") / TCP(sport=443, dport=40000, flags="SA")


class MatchRepliesTest(unittest.TestCase):
    def test_tcp_match(self):
        matches = match_replies([_syn_probe()], [_synack_reply()])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1][TCP].flags, "SA")

    def test_tcp_wrong_port_does_not_match(self):
        other = IP(src="203.0.113.9", dst="192.0.2.5") / TCP(sport=443, dport=40001, flags="SA")
        self.assertEqual(match_replies([_syn_probe()], [other]), [])

    def test_icmp_echo_match(self):
        probe = IP(src="192.0.2.5", dst="203.0.113.9") / ICMP(type=8, id=77)
        reply = IP(src="203.0.113.9", dst="192.0.2.5") / ICMP(type=0, id=77)
        self.assertEqual(len(match_replies([probe], [reply])), 1)

    def test_arp_match(self):
        probe = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="192.0.2.9")
        reply = Ether() / ARP(op=2, psrc="192.0.2.9", hwsrc="aa:bb:cc:00:00:01")
        self.assertEqual(len(match_replies([probe], [reply])), 1)


class OfflineCaptureTest(unittest.TestCase):
    def test_offline_capture_reads_all_packets(self):
        """End-to-end: synthetic trace -> pcap -> AsyncSniffer offline -> Capture."""
        trace, _meta = synthetic.build_trace("tcp_scan", seed=7, count=5)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trace.pcap")
            wrpcap(path, trace)
            cap = Capture(CaptureConfig(offline=path, count=5))
            cap.start()
            self.assertTrue(cap.wait(timeout=15))
            pkts = cap.stop()
            self.assertEqual(len(pkts), 5)
            self.assertEqual(cap.stats()["received"], 5)

    def test_write_pcap_roundtrip(self):
        trace, _ = synthetic.build_trace("syn_flood", seed=3, count=4)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.pcap")
            cap = Capture(CaptureConfig(offline=None))
            for p in trace:
                cap._on_packet(p)
            cap.write_pcap(path)
            self.assertEqual(len(rdpcap(path)), 4)


class EngineSendTest(unittest.TestCase):
    def test_send_dry_run_does_nothing(self):
        e = Engine(EngineConfig(dry_run=True))
        e.send(IP(dst="203.0.113.9") / ICMP())  # must not raise or send

    def test_send_list_dry_run_does_nothing(self):
        e = Engine(EngineConfig(dry_run=True))
        e.send([IP(dst="203.0.113.9") / ICMP() for _ in range(3)])


if __name__ == "__main__":
    unittest.main()
