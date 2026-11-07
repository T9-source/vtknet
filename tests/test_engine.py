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

    def test_rate_is_total_across_workers(self):
        e = Engine(EngineConfig(rate=100.0, workers=8))
        self.assertAlmostEqual(e._inter(), 8 / 100.0, places=4)  # per-worker pacing

    def test_workers_one_matches_legacy_inter(self):
        e = Engine(EngineConfig(rate=100.0, workers=1))
        self.assertAlmostEqual(e._inter(), 0.01, places=4)


class ConcurrencyTest(unittest.TestCase):
    """send_recv with workers>1 merges batch results in order (no network)."""

    def _engine(self, workers: int, batch_size: int, pkts) -> Engine:
        e = Engine(EngineConfig(workers=workers, batch_size=batch_size))
        calls: list[list[int]] = []

        def fake_chunk(chunk, l2, multi):
            calls.append([p[TCP].dport for p in chunk])
            answered = [(p, IP(src="10.0.0.9") / TCP(sport=p[TCP].dport, dport=1234, flags="SA")) for p in chunk]
            return answered, []

        e._run_chunk = fake_chunk  # type: ignore[method-assign]
        return e, calls

    def test_parallel_merges_in_batch_order(self):
        pkts = [IP(dst="10.0.0.1") / TCP(dport=p) for p in range(10)]
        e, calls = self._engine(workers=4, batch_size=2, pkts=pkts)
        answered, unanswered = e.send_recv(pkts)
        self.assertEqual(len(answered), 10)
        self.assertEqual([s[TCP].dport for s, _ in answered], list(range(10)))  # ordered
        self.assertEqual(unanswered, [])
        self.assertEqual(len(calls), 5)  # 10 pkts / batch 2

    def test_sequential_path_untouched(self):
        pkts = [IP(dst="10.0.0.1") / TCP(dport=p) for p in range(4)]
        e, calls = self._engine(workers=1, batch_size=2, pkts=pkts)
        answered, _ = e.send_recv(pkts)
        self.assertEqual(len(answered), 4)
        self.assertEqual(len(calls), 2)

    def test_single_batch_stays_sequential_even_with_workers(self):
        pkts = [IP(dst="10.0.0.1") / TCP(dport=p) for p in range(2)]
        e, calls = self._engine(workers=8, batch_size=64, pkts=pkts)
        answered, _ = e.send_recv(pkts)
        self.assertEqual(len(answered), 2)
        self.assertEqual(len(calls), 1)


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
