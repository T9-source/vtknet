"""TCP scanning with fully-controlled probe packets: SYN / NULL / FIN / XMAS / ACK."""

from __future__ import annotations

import logging
from enum import Enum

from scapy.all import ICMP, IP, TCP, RandShort
from scapy.packet import Packet

from vtknet.core.engine import Engine
from vtknet.core.models import Evidence, Finding, PortState

log = logging.getLogger("vtknet.scanner")


class ScanType(str, Enum):
    SYN = "syn"
    NULL = "null"
    FIN = "fin"
    XMAS = "xmas"
    ACK = "ack"


PROBE_FLAGS: dict[ScanType, str] = {
    ScanType.SYN: "S",
    ScanType.NULL: "",
    ScanType.FIN: "F",
    ScanType.XMAS: "FPU",
    ScanType.ACK: "A",
}

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04


def tcp_scan_packets(dst: str, ports: list[int], scan_type: ScanType) -> list[Packet]:
    """Build probe packets (pure function — no I/O, safe to unit-test)."""
    flags = PROBE_FLAGS[scan_type]
    return [IP(dst=dst) / TCP(sport=RandShort(), dport=p, flags=flags) for p in ports]


def classify_tcp_reply(scan_type: ScanType, reply: Packet | None) -> PortState:
    """Map a reply (or None) to a port state for the given probe type."""
    if reply is None:
        return PortState.FILTERED
    if reply.haslayer(ICMP):
        return PortState.FILTERED  # unreachable / rate-limit style response
    if not reply.haslayer(TCP):
        return PortState.FILTERED
    flags = int(reply[TCP].flags)
    if scan_type is ScanType.ACK:
        return PortState.UNFILTERED if flags & TCP_RST else PortState.FILTERED
    if flags & TCP_RST:
        return PortState.CLOSED
    if flags & TCP_SYN:
        return PortState.OPEN
    return PortState.FILTERED


def tcp_scan(
    engine: Engine, dst: str, ports: list[int], scan_type: ScanType
) -> tuple[list[Finding], dict[str, int]]:
    """Run the scan; open ports become findings, every state is counted in stats."""
    packets = tcp_scan_packets(dst, ports, scan_type)
    answered, unanswered = engine.send_recv(packets)
    counts: dict[str, int] = {s.value: 0 for s in PortState}
    findings: list[Finding] = []
    for sent, reply in answered:
        port = sent[TCP].dport
        state = classify_tcp_reply(scan_type, reply)
        counts[state.value] += 1
        if state is PortState.OPEN:
            findings.append(
                Finding(
                    module="scanner",
                    kind="port.open",
                    host=dst,
                    port=port,
                    state=state.value,
                    detail={
                        "scan": scan_type.value,
                        "flags": str(reply[TCP].flags),
                        "ttl": reply[IP].ttl if reply.haslayer(IP) else None,
                    },
                    evidence=[
                        Evidence("packet_hex", bytes(reply).hex(), f"{scan_type.value} probe reply")
                    ],
                )
            )
    counts[PortState.FILTERED.value] += len(unanswered)
    stats: dict[str, int] = {
        "sent": len(packets),
        "answered": len(answered),
        "unanswered": len(unanswered),
        **counts,
    }
    log.info("tcp %s scan of %s: %s", scan_type.value, dst, stats)
    return findings, stats
