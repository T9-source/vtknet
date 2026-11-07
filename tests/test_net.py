import unittest

from vtknet.utils.net import expand_hosts, parse_ports


class ParsePortsTest(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_comma(self):
        self.assertEqual(parse_ports("80,443"), [80, 443])

    def test_range_and_mix(self):
        self.assertEqual(parse_ports("443, 100-103, 80"), [80, 100, 101, 102, 103, 443])

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_bad_range_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("100-99")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports(" , ")


class ExpandHostsTest(unittest.TestCase):
    def test_cidr_excludes_network_and_broadcast(self):
        self.assertEqual(expand_hosts("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])

    def test_single_host_passthrough(self):
        self.assertEqual(expand_hosts("10.0.0.5"), ["10.0.0.5"])

    def test_ipv6_rejected_for_now(self):
        with self.assertRaises(ValueError):
            expand_hosts("2001:db8::/64")


if __name__ == "__main__":
    unittest.main()
