"""Seeded protocol fuzzer with liveness-based crash detection.

Mutations are drawn from a curated pool of boundary values applied to
fixed-size header fields (checksums, variable-length fields and the
destination address are never touched). A target is considered crashed when
it stops answering ICMP liveness probes after re-verification. Same seed →
same mutants, so a crash is reproducible byte-for-byte.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Iterator
from typing import Any

from scapy.all import ICMP, IP, TCP, UDP
from scapy.fields import Emph, PacketListField
from scapy.packet import Packet

from vtknet.core.engine import Engine
from vtknet.core.models import Evidence, Finding, Severity

log = logging.getLogger("vtknet.fuzz")

BASES = ("ip", "icmp", "udp", "tcp")


def _pool(bits: int) -> list[int]:
    """Boundary values for a field of ``bits`` bits."""
    vals = {0, 1, 2 ** (bits - 1) - 1, 2 ** (bits - 1), 2**bits - 1}
    if bits >= 8:
        vals.add(0xA5)
    if bits >= 16:
        vals.add(0xA5A5)
    return sorted(vals)


def _mutable_candidates(pkt: Packet) -> list[tuple[Packet, Any]]:
    """(layer-instance, field) pairs eligible for mutation."""
    cands: list[tuple[Packet, Any]] = []
    for layer in pkt.layers():
        inst = pkt.getlayer(layer)
        for f in inst.fields_desc:
            sz = getattr(f, "sz", 0) or 0
            if sz <= 0:
                continue  # variable-length fields are out of scope
            if f.name.endswith("chksum") or f.name == "options":
                continue  # auto-computed / nested structures
            if isinstance(f, (Emph, PacketListField)):
                continue  # never move the destination, never touch subpackets
            cands.append((inst, f))
    return cands


def mutate_packet(pkt: Packet, rng: random.Random) -> Packet:
    """Return a copy of pkt with exactly one header field replaced by a boundary value."""
    new = pkt.copy()
    cands = _mutable_candidates(new)
    if not cands:
        return new
    for _ in range(3):  # some fields reject exotic values — retry with another field
        inst, f = rng.choice(cands)
        bits = max(1, round(f.sz * 8))
        try:
            inst.setfieldval(f.name, rng.choice(_pool(bits)))
            return new
        except Exception as exc:  # noqa: BLE001 — a rejecting field is not a fuzzer failure
            log.debug("field %s rejected value: %s", f.name, exc)
            continue
    return new


def fuzz_variants(pkt: Packet, count: int, seed: int = 1337) -> Iterator[Packet]:
    """Deterministic stream of ``count`` mutated variants (per-variant seeded RNG)."""
    for i in range(count):
        yield mutate_packet(pkt, random.Random(f"{seed}-{i}"))


def _base_packet(dst: str, base: str, port: int | None, rng: random.Random) -> Packet:
    if base == "tcp":
        return IP(dst=dst) / TCP(sport=rng.randint(1024, 65535), dport=port or 80, flags="PA")
    if base == "udp":
        return IP(dst=dst) / UDP(sport=rng.randint(1024, 65535), dport=port or 53)
    if base == "icmp":
        return IP(dst=dst) / ICMP()
    if base == "ip":
        return IP(dst=dst)
    raise ValueError(f"unknown fuzz base: {base!r} (available: {', '.join(BASES)})")


# -- live loop -----------------------------------------------------------


def _host_alive(engine: Engine, dst: str) -> bool:
    return engine.send1(IP(dst=dst) / ICMP()) is not None


def _confirm_alive(engine: Engine, dst: str, recheck_delay: float) -> bool:
    if _host_alive(engine, dst):
        return True
    time.sleep(recheck_delay)
    return _host_alive(engine, dst)


def fuzz_target(
    engine: Engine,
    dst: str,
    *,
    count: int = 20,
    base: str = "tcp",
    port: int | None = None,
    seed: int = 1337,
    recheck_delay: float = 0.5,
    stop_on_crash: bool = True,
) -> tuple[list[Finding], dict[str, int]]:
    """Fuzz ``dst`` with seeded mutants; a lost liveness probe becomes a finding."""
    base_pkt = _base_packet(dst, base, port, random.Random(seed))
    if engine.cfg.dry_run:
        variants = list(fuzz_variants(base_pkt, min(count, 10), seed))
        log.info(
            "dry-run: would send %d %s mutant(s) to %s with ICMP liveness checks (seed=%d)",
            count,
            base,
            dst,
            seed,
        )
        for v in variants:
            log.info("dry-run: %s", v.summary())
        return [], {"mutants": count, "liveness_probes": 0, "crashes": 0}

    if not _host_alive(engine, dst):
        log.error("target %s is not answering liveness probes — aborting", dst)
        return (
            [
                Finding(
                    module="fuzz",
                    kind="fuzz.target.unreachable",
                    host=dst,
                    state="unreachable",
                )
            ],
            {"mutants": 0, "liveness_probes": 1, "crashes": 0},
        )

    findings: list[Finding] = []
    liveness_probes = 1
    sent = 0
    for i, mutant in enumerate(fuzz_variants(base_pkt, count, seed)):
        engine.send([mutant])
        sent += 1
        if _confirm_alive(engine, dst, recheck_delay):
            liveness_probes += 1
            continue
        liveness_probes += 2
        log.warning("target %s stopped answering after mutant #%d", dst, i)
        findings.append(
            Finding(
                module="fuzz",
                kind="fuzz.host.unresponsive",
                host=dst,
                severity=Severity.HIGH,
                detail={
                    "index": i,
                    "base": base,
                    "seed": seed,
                    "mutant": mutant.summary(),
                },
                evidence=[
                    Evidence(
                        "packet_hex", bytes(mutant).hex(), f"mutant #{i} preceded loss of liveness"
                    )
                ],
            )
        )
        if stop_on_crash:
            break

    stats = {"mutants": sent, "liveness_probes": liveness_probes, "crashes": len(findings)}
    log.info("fuzz %s (%s): %s", dst, base, stats)
    return findings, stats
