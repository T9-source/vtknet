import unittest

from scapy.all import ICMP, IP, TCP

from vtknet.core.engine import Engine, EngineConfig


class PacingTest(unittest.TestCase):
    def test_rate_sets_inter(self):
        e = Engine(EngineConfig(rate=100.0))
        self.assertAlmostEqual(e._inter(), 0.01, places=4)

    def test_rate_zero_disables_pacing(self):
        self.assertEqual(Engine(EngineConfig(rate=0))._inter(), 0.0)

    def test_jitter_raises_inter(self):
        self.assertGreaterEqual(Engine(EngineConfig(rate=100.0, jitter=0.05))._inter(), 0.01)

    def test_chunks_split_evenly(self):
        e = Engine(EngineConfig(batch_size=2))
        pkts = [IP(dst="10.0.0.1") / TCP(dport=p) for p in range(5)]
        self.assertEqual([len(c) for c in e._chunks(pkts)], [2, 2, 1])


class DryRunTest(unittest.TestCase):
    def test_dry_run_sends_nothing_probes_come_back_unanswered(self):
        e = Engine(EngineConfig(dry_run=True))
        pkts = [IP(dst="10.0.0.1") / TCP(dport=80, flags="S")]
        answered, unanswered = e.send_recv(pkts)
        self.assertEqual(answered, [])
        self.assertEqual(len(unanswered), 1)

    def test_send1_dry_run_returns_none(self):
        e = Engine(EngineConfig(dry_run=True))
        self.assertIsNone(e.send1(IP(dst="10.0.0.1") / ICMP()))

    def test_send_dry_run_is_silent_noop(self):
        e = Engine(EngineConfig(dry_run=True))
        e.send(IP(dst="10.0.0.1") / ICMP())
        e.send([IP(dst="10.0.0.1") / ICMP() for _ in range(3)])


if __name__ == "__main__":
    unittest.main()
