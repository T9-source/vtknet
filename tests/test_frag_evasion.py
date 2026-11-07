import unittest

from scapy.all import IP

from vtknet.modules.synthetic import build_trace


class FragEvasionTest(unittest.TestCase):
    def setUp(self):
        self.pkts, self.meta = build_trace("frag_evasion", seed=21, count=6)

    def test_fragment_count_and_framing(self):
        self.assertEqual(len(self.pkts), 6)
        for p in self.pkts:
            self.assertEqual(p.layers()[0].__name__, "Ether")  # homogeneous linktype

    def test_all_fragments_share_one_ip_id(self):
        ids = {p[IP].id for p in self.pkts}
        self.assertEqual(len(ids), 1)  # one logical stream

    def test_all_are_non_first_fragments_or_first(self):
        offsets = [p[IP].frag for p in self.pkts]
        self.assertEqual(len(set(offsets)), len(offsets))  # distinct offsets, no dupes
        self.assertTrue(any(o > 0 for o in offsets))  # someone is a continuation

    def test_order_is_shuffled_not_sequential(self):
        offsets = [p[IP].frag for p in self.pkts]
        self.assertNotEqual(offsets, sorted(offsets))  # deterministic seed shuffles

    def test_iocs_report_fragment_count(self):
        self.assertEqual(self.meta.iocs["fragments"], 6)


if __name__ == "__main__":
    unittest.main()
