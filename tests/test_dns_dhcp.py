import unittest

from scapy.all import BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, UDP, Ether

from vtknet.core.engine import EngineConfig
from vtknet.modules.dhcpprobe import analyze_offers, dhcp_discover_packets, dhcp_probe
from vtknet.modules.dnsprobe import (
    DEFAULT_RESOLVERS,
    dns_probe,
    dns_query_packet,
    extract_answers,
)

LAB_NAME = "lab.example"


def _dns_reply(resolver, rdata):
    return IP(src=resolver) / UDP(sport=53, dport=53535) / DNS(
        qr=1, ancount=1, qd=DNSQR(qname=LAB_NAME), an=DNSRR(rrname=LAB_NAME, rdata=rdata)
    )


class _MapEngine:
    """Duck-typed engine: replies keyed by destination (the resolver)."""

    def __init__(self, replies_by_dst, dry_run=False):
        self.cfg = EngineConfig(dry_run=dry_run)
        self._replies = replies_by_dst

    def send_recv(self, pkts, l2=False, multi=False):
        answered = [(p, self._replies[p[IP].dst]) for p in pkts if p[IP].dst in self._replies]
        return answered, [p for p in pkts if p[IP].dst not in self._replies]


class DnsBuilderTest(unittest.TestCase):
    def test_query_packet_fields(self):
        pkt = dns_query_packet(LAB_NAME, "192.0.2.53")
        self.assertEqual(pkt[IP].dst, "192.0.2.53")
        self.assertEqual(pkt[UDP].dport, 53)
        self.assertEqual(pkt[DNSQR].qname.rstrip(b".").decode(), LAB_NAME)
        self.assertEqual(pkt[DNSQR].qtype, 1)  # A

    def test_extract_answers_walks_chained_rr(self):
        reply = IP(src="192.0.2.53") / UDP(sport=53, dport=53535) / DNS(
            qr=1, ancount=2, qd=DNSQR(qname=LAB_NAME),
            an=DNSRR(rrname=LAB_NAME, rdata="192.0.2.7") / DNSRR(rrname=LAB_NAME, rdata="192.0.2.8"),
        )
        self.assertEqual(extract_answers(reply), ["192.0.2.7", "192.0.2.8"])

    def test_extract_answers_dissected_reply(self):
        # Real-world shape: bytes off the wire are re-dissected. scapy>=2.8
        # holds the RRs in the PacketListField view, not as a payload chain.
        reply = IP(src="192.0.2.53") / UDP(sport=53, dport=53535) / DNS(
            qr=1, ancount=2, qd=DNSQR(qname=LAB_NAME),
            an=DNSRR(rrname=LAB_NAME, rdata="192.0.2.7") / DNSRR(rrname=LAB_NAME, rdata="192.0.2.8"),
        )
        self.assertEqual(extract_answers(IP(bytes(reply))), ["192.0.2.7", "192.0.2.8"])

    def test_extract_answers_forged_ancount(self):
        # Hostile input: declared ancount far exceeds the RRs actually sent —
        # return what is present, never crash on the missing tail.
        reply = IP(src="192.0.2.53") / UDP(sport=53, dport=53535) / DNS(
            qr=1, ancount=9, qd=DNSQR(qname=LAB_NAME),
            an=DNSRR(rrname=LAB_NAME, rdata="192.0.2.7") / DNSRR(rrname=LAB_NAME, rdata="192.0.2.8"),
        )
        self.assertEqual(
            extract_answers(IP(bytes(reply))), ["192.0.2.7", "192.0.2.8"]
        )

    def test_non_dns_reply_is_empty(self):
        self.assertEqual(extract_answers(IP(src="192.0.2.53") / UDP(sport=53) / b"nope"), [])


class DnsFlowTest(unittest.TestCase):
    def test_consistent_answers(self):
        eng = _MapEngine({
            "192.0.2.53": _dns_reply("192.0.2.53", "192.0.2.7"),
            "192.0.2.54": _dns_reply("192.0.2.54", "192.0.2.7"),
        })
        findings, stats = dns_probe(eng, LAB_NAME, ["192.0.2.53", "192.0.2.54"])
        self.assertEqual(findings[0].kind, "dns.consistent")
        self.assertEqual(findings[0].detail["answers"], ["192.0.2.7"])
        self.assertEqual(stats["answered"], 2)

    def test_divergent_answers_is_high(self):
        eng = _MapEngine({
            "192.0.2.53": _dns_reply("192.0.2.53", "192.0.2.7"),
            "192.0.2.54": _dns_reply("192.0.2.54", "6.6.6.6"),
        })
        findings, _ = dns_probe(eng, LAB_NAME, ["192.0.2.53", "192.0.2.54"])
        self.assertEqual(findings[0].kind, "dns.divergent")
        self.assertEqual(findings[0].severity.value, "high")
        self.assertEqual(findings[0].detail["answers"]["192.0.2.54"], ["6.6.6.6"])

    def test_no_reply_is_filtered(self):
        eng = _MapEngine({})
        findings, stats = dns_probe(eng, LAB_NAME, ["192.0.2.53", "192.0.2.54"])
        self.assertEqual(findings[0].kind, "dns.no-response")
        self.assertEqual(stats["answered"], 0)

    def test_dry_run_sends_nothing(self):
        eng = _MapEngine({}, dry_run=True)
        findings, stats = dns_probe(eng, LAB_NAME, DEFAULT_RESOLVERS)
        self.assertEqual(findings, [])
        self.assertEqual(stats["sent"], 0)


def _offer(server_ip, yiaddr="192.0.2.50"):
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=server_ip) / UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=yiaddr, chaddr=b"\xaa" * 16) /
        DHCP(options=[("message-type", "offer"), ("server-id", server_ip), "end"])
    )


class DhcpBuilderTest(unittest.TestCase):
    def test_discover_packet_fields(self):
        pkt = dhcp_discover_packets()[0]
        self.assertEqual(pkt[Ether].dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(pkt[IP].src, "0.0.0.0")
        self.assertEqual(pkt[IP].dst, "255.255.255.255")
        self.assertEqual(pkt[UDP].dport, 67)
        self.assertEqual(pkt[BOOTP].op, 1)
        self.assertEqual(pkt[DHCP].options[0], ("message-type", "discover"))


class DhcpFlowTest(unittest.TestCase):
    @staticmethod
    def _pairs(*replies):
        sent = dhcp_discover_packets()[0]
        return [(sent, r) for r in replies]

    def test_single_server_found(self):
        findings, stats = analyze_offers(self._pairs(_offer("192.0.2.1")))
        self.assertEqual([f.kind for f in findings], ["dhcp.server-found"])
        self.assertEqual(findings[0].host, "192.0.2.1")
        self.assertEqual(stats["servers"], 1)

    def test_multiple_servers_is_medium(self):
        findings, stats = analyze_offers(
            self._pairs(_offer("192.0.2.1"), _offer("192.0.2.66"))
        )
        kinds = [f.kind for f in findings]
        self.assertIn("dhcp.server-found", kinds)
        self.assertIn("dhcp.multiple-servers", kinds)
        multi = next(f for f in findings if f.kind == "dhcp.multiple-servers")
        self.assertEqual(multi.severity.value, "medium")
        self.assertEqual(stats["servers"], 2)

    def test_unknown_server_with_known_config_is_high_rogue(self):
        findings, _ = analyze_offers(
            self._pairs(_offer("192.0.2.66")), known_server="192.0.2.1"
        )
        rogue = [f for f in findings if f.kind == "dhcp.rogue-suspected"]
        self.assertEqual(len(rogue), 1)
        self.assertEqual(rogue[0].severity.value, "high")
        self.assertEqual(rogue[0].detail["unexpected_servers"], ["192.0.2.66"])

    def test_known_server_responding_is_clean(self):
        findings, _ = analyze_offers(
            self._pairs(_offer("192.0.2.1")), known_server="192.0.2.1"
        )
        self.assertEqual([f.kind for f in findings], ["dhcp.server-found"])

    def test_no_offers_is_filtered(self):
        findings, _ = analyze_offers([])
        self.assertEqual(findings[0].kind, "dhcp.no-offers")
        self.assertEqual(findings[0].state, "filtered")

    def test_dry_run_sends_nothing(self):
        eng = _MapEngine({}, dry_run=True)
        findings, stats = dhcp_probe(eng)
        self.assertEqual(findings, [])
        self.assertEqual(stats["sent"], 0)


if __name__ == "__main__":
    unittest.main()
