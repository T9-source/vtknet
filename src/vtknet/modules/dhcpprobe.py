"""DHCP rogue-server detection: broadcast one discover, listen for every offer.

Exactly one trusted DHCP server should answer. A second offer — or any offer
that is not the known server — is the classic rogue-DHCP/MITM setup. Uses
``multi=True`` so every offer is collected, and snapshots/restores
``conf.checkIPaddr`` because DHCP replies are not address-mirrored.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf
from scapy.packet import Packet

from vtknet.core.engine import Engine
from vtknet.core.models import Finding, Severity

log = logging.getLogger("vtknet.dhcpprobe")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def dhcp_discover_packets(rng: random.Random | None = None) -> list[Packet]:
    """Pure builder: one DHCP discover broadcast (no I/O, safe to unit-test)."""
    rng = rng or random.Random()
    mac = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))
    return [
        Ether(dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=mac, xid=rng.getrandbits(32))
        / DHCP(options=[("message-type", "discover"), "end"])
    ]


def _offer_info(reply: Packet) -> dict[str, Any] | None:
    """Extract server identity + offered address from a DHCP offer (or None)."""
    if not reply.haslayer(DHCP) or not reply.haslayer(BOOTP) or not reply.haslayer(IP):
        return None
    opts = {k: v for k, v in (o for o in reply[DHCP].options if isinstance(o, tuple))}
    if opts.get("message-type") != "offer":
        return None
    reply_ip = reply[IP].src
    return {
        "server_id": str(opts.get("server-id", reply_ip)),
        "reply_from": reply_ip,
        "offer_ip": str(reply[BOOTP].yiaddr),
    }


def analyze_offers(
    offers: list[tuple[Packet, Packet]], known_server: str | None = None
) -> tuple[list[Finding], dict[str, int]]:
    """Classify collected offers: every server is a finding; multiples/unknowns escalate."""
    servers: dict[str, dict[str, Any]] = {}
    for _sent, rep in offers:
        info = _offer_info(rep)
        if info is not None:
            servers[info["server_id"]] = info

    findings: list[Finding] = []
    for sid, info in sorted(servers.items()):
        findings.append(
            Finding(
                module="dhcpprobe",
                kind="dhcp.server-found",
                host=sid,
                detail={"offer_ip": info["offer_ip"], "reply_from": info["reply_from"]},
            )
        )

    unexpected = (
        sorted(s for s in servers if known_server is not None and s != known_server)
        if known_server
        else []
    )
    if unexpected:
        findings.append(
            Finding(
                module="dhcpprobe",
                kind="dhcp.rogue-suspected",
                host=known_server or "-",
                severity=Severity.HIGH,
                detail={"known_server": known_server, "unexpected_servers": unexpected},
            )
        )
    elif len(servers) > 1:
        findings.append(
            Finding(
                module="dhcpprobe",
                kind="dhcp.multiple-servers",
                host="-",
                severity=Severity.MEDIUM,
                detail={"servers": sorted(servers)},
            )
        )
    elif not servers:
        findings.append(
            Finding(
                module="dhcpprobe",
                kind="dhcp.no-offers",
                host="-",
                state="filtered",
                detail={"known_server": known_server or ""},
            )
        )

    stats = {"sent": 1, "offers": len(offers), "servers": len(servers)}
    log.info("dhcp probe: %s", stats)
    return findings, stats


def dhcp_probe(
    engine: Engine, known_server: str | None = None
) -> tuple[list[Finding], dict[str, int]]:
    """Broadcast one discover and classify every offer (live, root)."""
    if engine.cfg.dry_run:
        log.info(
            "dry-run: would broadcast a DHCP discover and classify every offer "
            "(known_server=%s, no traffic)",
            known_server,
        )
        return [], {"sent": 0, "offers": 0, "servers": 0}

    old_check = conf.checkIPaddr
    conf.checkIPaddr = False  # DHCP replies are not address-mirrored
    try:
        packets = dhcp_discover_packets()
        answered, _unanswered = engine.send_recv(packets, l2=True, multi=True)
    finally:
        conf.checkIPaddr = old_check
    return analyze_offers(answered, known_server)
