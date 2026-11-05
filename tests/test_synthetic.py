import json
import os
import tempfile
import unittest

from scapy.all import IP, rdpcap

from vtknet.modules.synthetic import build_trace, list_scenarios, write_trace


class BuildTest(unittest.TestCase):
    def test_all_scenarios_build_requested_count(self):
        for name in list_scenarios():
            with self.subTest(scenario=name):
                pkts, meta = build_trace(name, seed=42, count=11)
                self.assertEqual(len(pkts), 11)
                self.assertEqual(meta.count, 11)

    def test_same_seed_is_byte_identical(self):
        a, _ = build_trace("syn_flood", seed=5, count=8)
        b, _ = build_trace("syn_flood", seed=5, count=8)
        self.assertEqual([bytes(p) for p in a], [bytes(p) for p in b])

    def test_different_seed_differs(self):
        a, _ = build_trace("syn_flood", seed=5, count=8)
        b, _ = build_trace("syn_flood", seed=6, count=8)
        self.assertNotEqual([bytes(p) for p in a], [bytes(p) for p in b])

    def test_unknown_scenario_rejected(self):
        with self.assertRaises(ValueError):
            build_trace("no_such_scenario")

    def test_documentation_ranges_used(self):
        pkts, _ = build_trace("syn_flood", seed=1, count=20)
        for p in pkts:
            self.assertTrue(
                p[IP].src.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
            )


class WriteTest(unittest.TestCase):
    def test_write_trace_pcap_and_sidecar(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trace.pcap")
            meta = write_trace("dns_tunnel", path, seed=9, count=6)
            self.assertEqual(len(rdpcap(path)), 6)
            with open(f"{path}.json", encoding="utf-8") as fh:
                sidecar = json.load(fh)
            self.assertEqual(sidecar["tool"], "vtknet")
            self.assertEqual(sidecar["name"], "dns_tunnel")
            self.assertEqual(sidecar["count"], 6)
            self.assertEqual(sidecar["iocs"]["queried_domain"], "example.com")
            self.assertTrue(meta.description)


if __name__ == "__main__":
    unittest.main()
