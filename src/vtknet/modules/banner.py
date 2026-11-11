"""Banner grabbing over scapy's TCP_client automaton.

Opens a stateful TCP conversation (SYN/ACK/retransmissions handled by the
supersocket), waits for the service to speak first, and captures the first
bytes as hex evidence — service identification from the server's own words,
not a port-number guess.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from vtknet.core.converse import link_recv_bounded
from vtknet.core.engine import Engine
from vtknet.core.models import Evidence, Finding

log = logging.getLogger("vtknet.banner")

WELL_KNOWN_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "tls",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
}


def _default_link_factory(dst: str, port: int) -> Any:
    """Userspace TCP conversation via scapy's TCP_client automaton (root needed)."""
    from scapy.all import Raw  # local: only needed when a live link is built
    from scapy.layers.inet import TCP_client  # local: pulls automaton machinery

    return TCP_client.tcplink(Raw, dst, port)


def summarize_banner(payload: bytes) -> str:
    """First printable line of the payload (control chars squashed, bounded)."""
    text = "".join(chr(b) if 32 <= b < 127 or b in (9,) else "." for b in payload[:256])
    line = text.split("\r")[0].split("\n")[0]
    return line[:200]


def banner_grab(
    engine: Engine,
    dst: str,
    port: int,
    read_bytes: int = 256,
    link_factory: Callable[[str, int], Any] | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Connect to dst:port and capture what the service says first.

    The raw reply bytes are kept as ``packet_hex`` evidence; the first
    printable line becomes ``banner``. Servers that wait for the client to
    speak (HTTP/1.1, TLS) produce ``banner.no-data`` — probe with ``tls``
    for those. The read is bounded by ``engine.cfg.timeout``: a server
    that accepts and stays silent can never hang the probe.
    """
    if engine.cfg.dry_run:
        log.info(
            "dry-run: would open a TCP conversation to %s:%d and read up to %d bytes",
            dst,
            port,
            read_bytes,
        )
        return [], {"sent": 0}

    factory = link_factory or _default_link_factory
    try:
        link = factory(dst, port)
    except Exception as exc:  # noqa: BLE001 — connect failures come in many shapes
        log.warning("could not open conversation to %s:%d: %s", dst, port, exc)
        return [
            Finding(
                module="banner",
                kind="banner.no-connection",
                host=dst,
                port=port,
                state="filtered",
                detail={"port": port, "service": WELL_KNOWN_PORTS.get(port)},
            )
        ], {"sent": 0}

    payload = link_recv_bounded(link, engine.cfg.timeout)[:read_bytes]
    try:
        link.close()
    except Exception as exc:  # noqa: BLE001 — closing an already-dead socket is not fatal
        log.debug("link close: %s", exc)

    if not payload:
        findings = [
            Finding(
                module="banner",
                kind="banner.no-data",
                host=dst,
                port=port,
                state="open",
                detail={"port": port, "service": WELL_KNOWN_PORTS.get(port)},
            )
        ]
    else:
        findings = [
            Finding(
                module="banner",
                kind="banner.grabbed",
                host=dst,
                port=port,
                state="open",
                detail={
                    "port": port,
                    "service": WELL_KNOWN_PORTS.get(port),
                    "banner": summarize_banner(payload),
                    "length": len(payload),
                },
                evidence=[Evidence("packet_hex", payload.hex(), f"first bytes from {dst}:{port}")],
            )
        ]
    stats = {"sent": 1, "bytes": len(payload)}
    log.info("banner %s:%d -> %s", dst, port, findings[0].kind)
    return findings, stats
