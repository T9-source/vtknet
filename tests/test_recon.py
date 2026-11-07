import unittest

from scapy.all import ARP, ICMP, IP, Ether

from vtknet.modules.recon import arp_scan_packets, icmp_sweep_packets


class BuilderTest(unittest.TestCase):
    def test_icmp_sweep_builds_echo_requests(self):
        pkts = icmp_sweep_packets(["10.0.0.1", "10.0.0.2"])
        self.assertEqual(len(pkts), 2)
        self.assertEqual(pkts[0][ICMP].type, 8)
        self.assertEqual(pkts[0][ICMP].code, 0)
        self.assertEqual(pkts[0][IP].dst, "10.0.0.1")

    def test_arp_scan_builds_broadcast_who_has(self):
        pkts = arp_scan_packets(["10.0.0.9"])
        self.assertEqual(pkts[0][Ether].dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(pkts[0][ARP].op, 1)
        self.assertEqual(pkts[0][ARP].pdst, "10.0.0.9")


if __name__ == "__main__":
    unittest.main()
