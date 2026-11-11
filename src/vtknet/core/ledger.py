"""Ledger reconciliation — double-entry bookkeeping for the wire.

Every packet that lands on our addresses is a credit; probes we sent are
the debits. ``ledger_unsolicited`` audits a capture and reports every
remote talker whose traffic is NOT accounted for by our own probes —
"the network spoke first". Scanners from other machines, worms, ghost
replies, unsolicited resets: all become findings with packet evidence.
Everything must balance.
"""

from __future__ import annotations

import logging

from scapy.all import IP, TCP, UDP, IPv6

from vtknet.core.models import Evidence, Finding, Severity

log = logging.getLogger("vtknet.ledger")

MAX_TALKERS = 256  # hostile-traffic cap: millions of sources must not explode


def _our_ips() -> set[str]:
    """Local addresses (best effort) — credits to these count as inbound."""
    import socket

    ours = {"127.0.0.1"}
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            ours.add(info[4][0])
    except OSError:
        pass
    return ours


def ledger_unsolicited(
    packets: list, our_ips: set[str] | None = None
) -> tuple[list[Finding], dict[str, int]]:
    """Findings for every unaccounted remote talker in a capture.

    A packet counts as inbound credit when its destination is one of ours
    and its source is not. Talkers are grouped by (src, proto, dport);
    the first packet of each group becomes the evidence.
    """
    ours = our_ips if our_ips is not None else _our_ips()
    talkers: dict[tuple, dict] = {}
    inbound = 0
    for pkt in packets:
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            continue
        if dst not in ours or src in ours:
            continue  # not addressed to us, or our own echo
        inbound += 1
        if pkt.haslayer(TCP):
            proto, port = "tcp", int(pkt[TCP].sport)
        elif pkt.haslayer(UDP):
            proto, port = "udp", int(pkt[UDP].sport)
        else:
            proto, port = "ip", 0
        key = (src, proto, port)
        entry = talkers.get(key)
        if entry is None:
            if len(talkers) >= MAX_TALKERS:
                continue  # hostile flood: cap the census, count the inbound
            entry = talkers[key] = {"count": 0, "first": pkt}
        entry["count"] += 1

    findings = [
        Finding(
            module="ledger",
            kind="ledger.unsolicited",
            host=src,
            severity=Severity.INFO,
            detail={"proto": proto, "src_port": port, "packets": entry["count"]},
            evidence=[
                Evidence(
                    "packet_hex",
                    bytes(entry["first"]).hex(),
                    f"first packet from {src}:{port}/{proto}",
                )
            ],
        )
        for (src, proto, port), entry in talkers.items()
    ]
    stats = {"inbound": inbound, "talkers": len(talkers)}
    log.info("ledger: %d inbound packet(s), %d unaccounted talker(s)", inbound, len(talkers))
    return findings, stats
