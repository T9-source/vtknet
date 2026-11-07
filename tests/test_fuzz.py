import unittest

from scapy.all import ICMP, IP, TCP

from vtknet.core.engine import EngineConfig
from vtknet.modules.fuzz import _pool, fuzz_target, fuzz_variants, mutate_packet

BASE = IP(dst="203.0.113.9") / TCP(dport=80, flags="PA")


class PoolTest(unittest.TestCase):
    def test_pool_within_bounds(self):
        for bits in (1, 4, 8, 9, 16, 32):
            for v in _pool(bits):
                self.assertGreaterEqual(v, 0)
                self.assertLess(v, 2**bits)


class MutationTest(unittest.TestCase):
    def test_deterministic_variants(self):
        a = [bytes(p) for p in fuzz_variants(BASE, 5, seed=9)]
        b = [bytes(p) for p in fuzz_variants(BASE, 5, seed=9)]
        self.assertEqual(a, b)

    def test_variants_differ_across_seeds(self):
        a = [bytes(p) for p in fuzz_variants(BASE, 5, seed=1)]
        b = [bytes(p) for p in fuzz_variants(BASE, 5, seed=2)]
        self.assertTrue(any(x != y for x, y in zip(a, b)))

    def test_mutants_build_cleanly(self):
        for m in fuzz_variants(BASE, 10, seed=3):
            m.build()  # must never raise

    def test_destination_never_mutated(self):
        for m in fuzz_variants(BASE, 20, seed=11):
            self.assertEqual(m[IP].dst, "203.0.113.9")

    def test_mutate_packet_changes_something(self):
        mutated = [bytes(mutate_packet(BASE, __import__("random").Random(42))) for _ in range(1)]
        self.assertNotEqual(mutated[0], bytes(BASE))


class DyingEngine:
    """Alive while fewer than dies_after packets have been sent, then dead."""

    def __init__(self, dies_after: int) -> None:
        self.cfg = EngineConfig()
        self.sent = 0
        self.dies_after = dies_after

    def send(self, pkts, l2: bool = False) -> None:
        self.sent += len(pkts)

    def send1(self, pkt, l2: bool = False):
        return None if self.sent >= self.dies_after else IP(src="203.0.113.9") / ICMP(type=0)


class CrashDetectionTest(unittest.TestCase):
    def test_crash_detected_with_evidence(self):
        eng = DyingEngine(dies_after=4)
        findings, stats = fuzz_target(
            eng, "203.0.113.9", count=10, base="icmp", seed=1, recheck_delay=0.0
        )
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, "fuzz.host.unresponsive")
        self.assertEqual(f.severity.value, "high")
        self.assertEqual(f.evidence[0].kind, "packet_hex")
        self.assertEqual(stats["crashes"], 1)
        self.assertEqual(stats["mutants"], 4)  # stops at the crashing mutant

    def test_unreachable_target_aborts(self):
        eng = DyingEngine(dies_after=0)
        findings, stats = fuzz_target(eng, "203.0.113.9", count=5, recheck_delay=0.0)
        self.assertEqual(findings[0].kind, "fuzz.target.unreachable")
        self.assertEqual(stats["mutants"], 0)

    def test_healthy_target_yields_no_crash(self):
        eng = DyingEngine(dies_after=10**9)
        findings, stats = fuzz_target(eng, "203.0.113.9", count=3, recheck_delay=0.0)
        self.assertEqual(findings, [])
        self.assertEqual(stats["crashes"], 0)
        self.assertEqual(stats["mutants"], 3)


if __name__ == "__main__":
    unittest.main()
