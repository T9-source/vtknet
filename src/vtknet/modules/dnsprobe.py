"""DNS consistency probing: ask several resolvers the same question and compare.

Divergent answers between independent resolvers are the classic symptom of
DNS spoofing/poisoning on the path. Honest caveat: CDNs legitimately answer
differently per region — divergence is a *suspected* spoofing finding (HIGH)
whose detail carries the per-resolver answers so a human judges the split.
"""

from __future__ import annotations

import logging
import random

from scapy.all import DNS, DNSQR, IP, UDP
from scapy.packet import Packet

from vtknet.core.engine import Engine
from vtknet.core.models import Evidence, Finding, Severity

log = logging.getLogger("vtknet.dnsprobe")

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def dns_query_packet(name: str, resolver: str, qtype: str = "A", sport: int = 53535) -> Packet:
    """Pure builder: one DNS query to one resolver (no I/O, safe to unit-test)."""
    return IP(dst=resolver) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype))


def extract_answers(reply: Packet) -> list[str]:
    """Walk the chained answer RRs of a DNS reply into a list of rdata strings."""
    if not reply.haslayer(DNS):
        return []
    d = reply[DNS]
    out: list[str] = []
    rr = d.an
    for _ in range(d.ancount):
        if rr is None:
            break
        out.append(str(rr.rdata))
        rr = rr.payload
    return out


def dns_probe(
    engine: Engine,
    name: str,
    resolvers: list[str] | None = None,
    qtype: str = "A",
) -> tuple[list[Finding], dict[str, int]]:
    """Ask every resolver the same question; classify agreement/divergence."""
    resolvers = resolvers or DEFAULT_RESOLVERS
    if engine.cfg.dry_run:
        log.info(
            "dry-run: would ask %d resolver(s) for %s %s and compare answers (no traffic)",
            len(resolvers),
            name,
            qtype,
        )
        return [], {"sent": 0, "resolvers": len(resolvers)}

    sport = random.randint(1024, 65535)
    packets = [dns_query_packet(name, r, qtype, sport) for r in resolvers]
    answered, _unanswered = engine.send_recv(packets)

    answers_by: dict[str, list[str]] = {}
    first_reply_hex: str | None = None
    for sent, rep in answered:
        resolver = sent[IP].dst
        if rep.haslayer(DNS):
            answers_by[resolver] = extract_answers(rep)
            if first_reply_hex is None:
                first_reply_hex = bytes(rep).hex()
    no_reply = [r for r in resolvers if r not in answers_by]

    findings: list[Finding] = []
    distinct = {tuple(sorted(a)) for a in answers_by.values()} if answers_by else set()
    if not answers_by:
        findings.append(
            Finding(
                module="dnsprobe",
                kind="dns.no-response",
                host=name,
                state="filtered",
                detail={"resolvers": resolvers, "qtype": qtype},
            )
        )
    elif len(distinct) == 1:
        findings.append(
            Finding(
                module="dnsprobe",
                kind="dns.consistent",
                host=name,
                detail={
                    "qtype": qtype,
                    "answers": sorted(next(iter(distinct))),
                    "resolvers_agreeing": len(answers_by),
                    "no_reply": no_reply,
                },
            )
        )
    else:
        evidence = (
            [Evidence("packet_hex", first_reply_hex, "divergent resolver reply")]
            if first_reply_hex
            else []
        )
        findings.append(
            Finding(
                module="dnsprobe",
                kind="dns.divergent",
                host=name,
                severity=Severity.HIGH,
                detail={"qtype": qtype, "answers": answers_by, "no_reply": no_reply},
                evidence=evidence,
            )
        )

    stats = {
        "sent": len(resolvers),
        "answered": len(answers_by),
        "no_reply": len(no_reply),
    }
    log.info("dns probe %s (%s): %s", name, qtype, stats)
    return findings, stats
