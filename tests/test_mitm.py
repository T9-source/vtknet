import os
import tempfile
import threading
import time
import unittest

from scapy.all import ARP, Ether

from vtknet.core.engine import EngineConfig
from vtknet.modules.mitm import ArpSpoofer, poison_packets, restore_packets

VICTIM_IP, VICTIM_MAC = "192.0.2.10", "aa:bb:cc:00:00:10"
GATEWAY_IP, GATEWAY_MAC = "192.0.2.1", "aa:bb:cc:00:00:01"
MY_MAC = "aa:bb:cc:00:00:99"


class SpoofEngine:
    """Duck-typed engine: ARP who-has gets canned replies; sends are recorded."""

    def __init__(self) -> None:
        self.cfg = EngineConfig()
        self.sent: list = []
        self._lock = threading.Lock()

    def send1(self, pkt, l2: bool = False):
        if pkt.haslayer(ARP):
            dst = pkt[ARP].pdst
            return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=dst, hwsrc=MACS[dst])
        return None

    def send(self, pkts, l2: bool = False) -> None:
        with self._lock:
            for p in pkts:
                self.sent.append(p)


MACS = {VICTIM_IP: VICTIM_MAC, GATEWAY_IP: GATEWAY_MAC}


class BuildersTest(unittest.TestCase):
    def test_poison_binds_gateway_to_attacker(self):
        pkts = poison_packets(VICTIM_IP, VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC, MY_MAC)
        self.assertEqual(len(pkts), 2)
        p = pkts[0]
        self.assertEqual(p[Ether].dst, VICTIM_MAC)
        self.assertEqual(p[ARP].op, 2)
        self.assertEqual(p[ARP].psrc, GATEWAY_IP)
        self.assertEqual(p[ARP].hwsrc, MY_MAC)  # the lie
        self.assertEqual(p[ARP].pdst, VICTIM_IP)

    def test_restore_binds_real_macs(self):
        pkts = restore_packets(VICTIM_IP, VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC)
        self.assertEqual(pkts[0][ARP].psrc, GATEWAY_IP)
        self.assertEqual(pkts[0][ARP].hwsrc, GATEWAY_MAC)  # the truth
        self.assertEqual(pkts[1][ARP].psrc, VICTIM_IP)
        self.assertEqual(pkts[1][ARP].hwsrc, VICTIM_MAC)


class LifecycleTest(unittest.TestCase):
    def test_start_poisons_stop_restores_and_reverts_forward(self):
        eng = SpoofEngine()
        with tempfile.TemporaryDirectory() as d:
            fwd = os.path.join(d, "ip_forward")
            with open(fwd, "w") as fh:
                fh.write("0\n")
            spoof = ArpSpoofer(
                eng, VICTIM_IP, GATEWAY_IP, interval=0.01, forward_path=fwd
            )
            spoof.start()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and spoof.poisons_sent == 0:
                time.sleep(0.02)
            st = spoof.stop()

            self.assertEqual(spoof.victim_mac, VICTIM_MAC)
            self.assertEqual(spoof.gateway_mac, GATEWAY_MAC)
            self.assertGreater(st["poisons_sent"], 0)
            self.assertEqual(st["restores_sent"], 6)  # 3 rounds x 2 directions
            self.assertTrue(st["forward_restored"])
            with open(fwd) as fh:
                self.assertEqual(fh.read().strip(), "0")
            # the very last two packets must be the correct bindings
            expected = [bytes(p) for p in restore_packets(VICTIM_IP, VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC)]
            self.assertEqual([bytes(p) for p in eng.sent[-2:]], expected)

    def test_unresolvable_mac_raises(self):
        eng = SpoofEngine()
        eng.send1 = lambda pkt, l2=False: None  # type: ignore[method-assign]
        spoof = ArpSpoofer(eng, VICTIM_IP, GATEWAY_IP, manage_forward=False)
        with self.assertRaises(RuntimeError):
            spoof.start()

    def test_dry_run_is_silent(self):
        eng = SpoofEngine()
        eng.cfg = EngineConfig(dry_run=True)
        spoof = ArpSpoofer(eng, VICTIM_IP, GATEWAY_IP)
        spoof.start()
        st = spoof.stop()
        self.assertEqual(eng.sent, [])
        self.assertIsNone(st["victim_mac"])


if __name__ == "__main__":
    unittest.main()
