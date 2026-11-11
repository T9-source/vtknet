"""Evidence is executable: re-send the exact bytes a finding was proven with.

``vtk replay REPORT --finding ID`` loads a saved report, takes the finding's
first ``packet_hex`` evidence, decodes it back into a packet and sends it
again through the Engine — the crashing fuzz mutant, the exact probe that
produced an anomaly, re-fired byte-for-byte. Dry-run aware: the built
packet is logged, nothing leaves the host.
"""

from __future__ import annotations

import logging
from typing import Any

from vtknet.core.engine import Engine
from vtknet.core.inspect import decode_bytes
from vtknet.core.models import Finding, Severity

log = logging.getLogger("vtknet.replay")


def load_report(path: str, pub: str | None = None) -> dict[str, Any]:
    """Load a plain or DSSE-wrapped report file as a report dict.

    Envelopes are verified before use (fail closed) against ``pub`` —
    or the newest staged public key when none is given.
    """
    import json
    from pathlib import Path

    from vtknet.core.signing import DEFAULT_KEYS_DIR, is_envelope, verify_envelope

    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read report ({path}): {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"not a valid vtknet JSON report ({path}): {exc}") from exc
    if is_envelope(parsed):
        return json.loads(verify_envelope(parsed, pub or _newest_pub(DEFAULT_KEYS_DIR)))
    if not isinstance(parsed, dict) or "findings" not in parsed:
        raise ValueError(f"not a vtknet report (missing 'findings'): {path}")
    return parsed


def _newest_pub(directory) -> str:
    from pathlib import Path

    keys = sorted(Path(directory).glob("*.pub"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not keys:
        raise ValueError(f"no *.pub found in {directory} — pass the public key or run 'vtk keygen'")
    return str(keys[0])


def find_finding_evidence(report: dict[str, Any], finding_id: str) -> str:
    """First packet_hex evidence of the named finding; raises ValueError otherwise."""
    for f in report.get("findings", []):
        if str(f.get("id")) == finding_id:
            for ev in f.get("evidence", []):
                if ev.get("kind") == "packet_hex" and ev.get("data"):
                    return ev["data"]
            raise ValueError(f"finding {finding_id!r} has no packet_hex evidence to replay")
    known = [str(f.get("id")) for f in report.get("findings", [])][:10]
    raise ValueError(f"finding {finding_id!r} not in report (first ids: {known})")


def replay_finding(
    engine: Engine, evidence_hex: str, count: int = 1
) -> tuple[list[Finding], dict[str, int]]:
    """Decode evidence hex into a packet and send it ``count`` times."""
    if count < 1:
        raise ValueError("count must be >= 1")
    try:
        pkt = decode_bytes(bytes.fromhex(evidence_hex))
    except ValueError as exc:  # bad hex
        raise ValueError(f"evidence is not decodable hex: {exc}") from exc
    from scapy.all import IP  # local: layer class for host extraction

    engine.send([pkt] * count)
    findings = [
        Finding(
            module="replay",
            kind="replay.sent",
            host=str(pkt[IP].dst) if pkt.haslayer(IP) else "-",
            severity=Severity.INFO,
            detail={"bytes": len(bytes(pkt)), "count": count, "summary": pkt.summary()},
        )
    ]
    stats = {"sent": count}
    log.info("replayed evidence packet x%d (%d bytes)", count, len(bytes(pkt)))
    return findings, stats
