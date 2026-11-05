"""Host discovery modules: ICMP echo sweep and ARP scan."""

from __future__ import annotations

import logging

from scapy.all import ARP, ICMP, IP, Ether
from scapy.packet import Packet

from vtknet.core.engine import Engine
from vtknet.core.models import Evidence, Finding

log = logging.getLogger("vtknet.recon")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def icmp_sweep_packets(hosts: list[str]) -> list[Packet]:
    """Echo requests for the given hosts (pure builder — no I/O, safe to unit-test)."""
    return [IP(dst=h) / ICMP(type=8, code=0) for h in hosts]


def arp_scan_packets(hosts: list[str]) -> list[Packet]:
    """Who-has requests for the given addresses (pure builder — no I/O)."""
    return [Ether(dst=BROADCAST_MAC) / ARP(op=1, pdst=h) for h in hosts]


def ping_sweep(engine: Engine, hosts: list[str]) -> tuple[list[Finding], dict[str, int]]:
    """ICMP echo sweep; returns (findings, stats)."""
    packets = icmp_sweep_packets(hosts)
    answered, unanswered = engine.send_recv(packets)
    findings: list[Finding] = []
    for sent, reply in answered:
        src = reply[IP].src
        mac = reply[Ether].src if reply.haslayer(Ether) else "?"
        findings.append(
            Finding(
                module="recon",
                kind="host.alive",
                host=src,
                detail={
                    "mac": mac,
                    "ttl": reply[IP].ttl,
                    "probe": "icmp-echo",
                    "asked": sent[IP].dst,
                },
                evidence=[Evidence("packet_hex", bytes(reply).hex(), f"echo reply from {src}")],
            )
        )
    stats = {"sent": len(packets), "answered": len(answered), "unanswered": len(unanswered)}
    log.info("ping sweep: %d host(s), %d alive", len(hosts), len(findings))
    return findings, stats


def arp_scan(engine: Engine, hosts: list[str]) -> tuple[list[Finding], dict[str, int]]:
    """ARP who-has scan of a local segment; returns (findings, stats)."""
    packets = arp_scan_packets(hosts)
    answered, unanswered = engine.send_recv(packets, l2=True)
    findings: list[Finding] = []
    for sent, reply in answered:
        src = reply[ARP].psrc
        mac = reply[ARP].hwsrc
        findings.append(
            Finding(
                module="recon",
                kind="host.arp-entry",
                host=src,
                detail={"mac": mac, "asked": sent[ARP].pdst},
                evidence=[Evidence("packet_hex", bytes(reply).hex(), f"ARP reply for {src}")],
            )
        )
    stats = {"sent": len(packets), "answered": len(answered), "unanswered": len(unanswered)}
    log.info("arp scan: %d host(s), %d replies", len(hosts), len(findings))
    return findings, stats
