"""QUIC reachability probing via RFC 9000 Version Negotiation.

Any QUIC endpoint that receives a long-header packet carrying an unsupported
version MUST reply with a Version Negotiation (VN) packet listing the
versions it supports. That makes VN a standards-mandated, crypto-free QUIC
reachability check: one UDP datagram in, one answer out.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from scapy.all import ICMP, IP, UDP
from scapy.packet import Packet

from vtknet.core.engine import Engine
from vtknet.core.models import Evidence, Finding

log = logging.getLogger("vtknet.quic")

# RFC 9000 §15: versions of the form ?a?b?c?d force version negotiation.
VN_PROBE_VERSION = 0x1A2A3A4A


def build_vn_probe_bytes(dcid: bytes, scid: bytes = b"") -> bytes:
    """Hand-built QUIC long-header datagram with a forced-VN version (pure, deterministic)."""
    out = bytearray()
    out.append(0xC0)  # long header, fixed bit set
    out += VN_PROBE_VERSION.to_bytes(4, "big")
    out.append(len(dcid))
    out += dcid
    out.append(len(scid))
    out += scid
    return bytes(out)


def quic_probe_packets(
    dst: str, port: int = 443, rng: random.Random | None = None
) -> list[Packet]:
    """Build the probe datagram(s) (pure builder — no I/O, safe to unit-test)."""
    rng = rng or random.Random()
    dcid = rng.getrandbits(64).to_bytes(8, "big")  # 8-byte DCID, like real clients
    return [
        IP(dst=dst)
        / UDP(sport=rng.randint(1024, 65535), dport=port)
        / build_vn_probe_bytes(dcid)
    ]


def parse_version_negotiation(payload: bytes) -> dict[str, Any] | None:
    """Classify a UDP payload: VN packet -> supported versions; None -> not QUIC VN."""
    if len(payload) < 6 or not (payload[0] & 0x80):
        return None  # short header / too small
    if int.from_bytes(payload[1:5], "big") != 0:
        return None  # long header with a real version — a serverHello, not VN
    i = 5
    try:
        dlen = payload[i]
        i += 1 + dlen
        slen = payload[i]
        i += 1 + slen
    except IndexError:
        return {"kind": "quic.vn-malformed"}
    versions = []
    while i + 4 <= len(payload):
        versions.append(f"0x{int.from_bytes(payload[i : i + 4], 'big'):08x}")
        i += 4
    if not versions:
        return {"kind": "quic.vn-malformed"}
    return {"kind": "quic.version-negotiation", "versions": versions}


def quic_probe(
    engine: Engine, dst: str, port: int = 443
) -> tuple[list[Finding], dict[str, int]]:
    """Send one VN probe; classify the answer (or its absence) into findings."""
    if engine.cfg.dry_run:
        pkt = quic_probe_packets(dst, port)[0]
        log.info(
            "dry-run: %s — would send a %d-byte QUIC VN probe to %s:%d (no traffic)",
            pkt.summary(),
            len(build_vn_probe_bytes(b"\x11" * 8)),
            dst,
            port,
        )
        return [], {"sent": 0}

    rep = engine.send1(quic_probe_packets(dst, port)[0])
    if rep is None:
        return [_finding(dst, "quic.no-response", port, state="filtered")], {"sent": 1}
    if rep.haslayer(ICMP):  # e.g. port unreachable from a non-QUIC host
        return [_finding(dst, "quic.unreachable", port, state="closed")], {"sent": 1}
    if not rep.haslayer(UDP):
        return [_finding(dst, "quic.no-response", port, state="filtered")], {"sent": 1}

    payload = bytes(rep[UDP].payload)
    info = parse_version_negotiation(payload)
    if info is None:
        return [
            Finding(
                module="quicprobe",
                kind="quic.non-quic-reply",
                host=dst,
                port=port,
                state="open",
                detail={"port": port, "payload_hex": payload[:32].hex()},
                evidence=[Evidence("packet_hex", payload.hex(), "UDP reply payload")],
            )
        ], {"sent": 1}
    if info["kind"] != "quic.version-negotiation":
        return [_finding(dst, info["kind"], port, state="open")], {"sent": 1}

    findings = [
        Finding(
            module="quicprobe",
            kind="quic.version-negotiation",
            host=dst,
            port=port,
            state="open",
            detail={"port": port, **info},
            evidence=[Evidence("packet_hex", payload.hex(), "version negotiation packet")],
        )
    ]
    log.info("quic probe %s:%d -> %s", dst, port, info["versions"])
    return findings, {"sent": 1}


def _finding(dst: str, kind: str, port: int, state: str | None = None) -> Finding:
    return Finding(module="quicprobe", kind=kind, host=dst, port=port, state=state)
