"""Robustness: hostile/truncated pcaps and garbage bytes must never crash parsers."""

import os
import tempfile
import unittest

from scapy.all import IP, TCP, Ether, wrpcap

from vtknet.core.capture import iter_pcap_safe
from vtknet.core.inspect import decode_bytes, pcap_summary


class IterPcapSafeTest(unittest.TestCase):
    def test_valid_pcap_yields_everything(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ok.pcap")
            wrpcap(path, [Ether() / IP(dst="203.0.113.9") / TCP(dport=p, flags="S") for p in range(5)])
            stats: dict = {}
            pkts = list(iter_pcap_safe(path, stats=stats))
            self.assertEqual(len(pkts), 5)
            self.assertEqual(stats["malformed"], 0)

    def test_truncated_tail_is_skipped_not_fatal(self):
        """Valid records followed by garbage bytes: the valid ones always survive.

        scapy is lenient — garbage tails often dissect into junk "packets"
        rather than raising. Our guarantee: valid records are never lost and
        nothing ever crashes.
        """
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "corrupt.pcap")
            wrpcap(path, [Ether() / IP(dst="203.0.113.9") / TCP(dport=p, flags="S") for p in range(4)])
            with open(path, "ab") as fh:
                fh.write(b"\xde\xad\xbe\xef" * 40)  # truncated/garbage record tail
            stats: dict = {}
            pkts = list(iter_pcap_safe(path, stats=stats))
            self.assertGreaterEqual(len(pkts), 4)  # valid records survived
            self.assertLessEqual(len(pkts), 5)  # at most one junk-packet artifact

    def test_pure_garbage_file_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "garbage.pcap")
            with open(path, "wb") as fh:
                fh.write(os.urandom(2048))
            with self.assertRaises(ValueError):
                list(iter_pcap_safe(path))


class PcapSummaryRobustnessTest(unittest.TestCase):
    def test_corrupt_pcap_reports_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "garbage.pcap")
            with open(path, "wb") as fh:
                fh.write(os.urandom(2048))
            with self.assertRaises(ValueError):
                pcap_summary(path)

    def test_pcap_with_garbage_tail_still_summarizes(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "corrupt.pcap")
            wrpcap(path, [Ether() / IP(dst="203.0.113.9") / TCP(dport=p, flags="S") for p in range(4)])
            with open(path, "ab") as fh:
                fh.write(b"\xde\xad\xbe\xef" * 40)
            s = pcap_summary(path)
            self.assertGreaterEqual(s["packets"], 4)  # valid records summarized
            if len(s["layers_seen"]) < s["packets"]:  # junk artifact was present
                self.assertGreaterEqual(s["junk_suspect"], 1)
            self.assertNotIn("Raw", s["layers_seen"])  # opaque frames never pollute stats

    def test_unique_key_cap_prevents_oom(self):
        """A pcap with more unique conversations than the cap sets 'truncated'."""
        from vtknet.core import inspect as inspect_mod

        pkts = []
        for p in range(20):
            pkts.append(
                Ether() / IP(src=f"192.0.2.{p % 250 + 1}", dst="203.0.113.9") / TCP(sport=p, dport=80, flags="S")
            )
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "many.pcap")
            wrpcap(path, pkts)
            original = inspect_mod.MAX_UNIQUE_KEYS
            inspect_mod.MAX_UNIQUE_KEYS = 5  # shrink the cap for a fast test
            try:
                s = pcap_summary(path)
            finally:
                inspect_mod.MAX_UNIQUE_KEYS = original
        self.assertTrue(s["truncated"])
        self.assertLessEqual(len(s["top_conversations"]), 10)


class DecodeHostileTest(unittest.TestCase):
    def test_garbage_bytes_never_raise(self):
        for blob in (b"", b"\xff" * 64, os.urandom(256), b"\x45" + os.urandom(19)):
            pkt = decode_bytes(blob)  # must not raise
            self.assertTrue(pkt is not None)

    def test_valid_bytes_still_decode(self):
        pkt = decode_bytes(bytes(IP(dst="203.0.113.9") / TCP(dport=443, flags="S")))
        self.assertEqual([l.__name__ for l in pkt.layers()], ["IP", "TCP"])


if __name__ == "__main__":
    unittest.main()
