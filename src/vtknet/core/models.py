"""Structured data model for every toolkit result.

Every module produces ``Finding`` objects; a run produces a ``ScanResult``
that serializes to stable JSON. Findings carry evidence (raw packet bytes)
so every claim in a report is verifiable byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> str:
    """ISO-8601 UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"  # no reply, or ICMP unreachable
    UNFILTERED = "unfiltered"  # got RST to an ACK probe
    OPEN_FILTERED = "open|filtered"


def sha256_hex(data: str) -> str:
    """SHA-256 over the UTF-8 bytes of ``data`` — chain-of-custody anchor."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class Evidence:
    """A verifiable artifact backing a Finding (packet hex or pcap path).

    ``sha256`` is stamped at creation over the exact serialized ``data``
    (hex bytes or file path) — the first link of the verify/sign chain.
    """

    kind: str  # "packet_hex" | "certificate_der" | "pcap"
    data: str  # hex bytes or file path
    note: str = ""
    sha256: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = sha256_hex(self.data)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "data": self.data, "note": self.note, "sha256": self.sha256}


@dataclass
class Finding:
    """One claim with proof. Machine label in ``kind``, human context in ``detail``."""

    module: str  # producing module: "recon", "scanner", ...
    kind: str  # machine label: "host.alive", "port.open", ...
    host: str
    port: int | None = None
    state: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    severity: Severity = Severity.INFO
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "module": self.module,
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "severity": self.severity.value,
            "detail": dict(self.detail),
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class ScanResult:
    """Top-level result of one CLI run."""

    command: str
    args: dict[str, Any] = field(default_factory=dict)
    started: str = field(default_factory=utcnow)
    finished: str = ""
    duration_s: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def finish(self, duration_s: float) -> None:
        """Stamp completion time and duration (call once, at the end of the run)."""
        self.finished = utcnow()
        self.duration_s = round(duration_s, 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "args": self.args,
            "started": self.started,
            "finished": self.finished,
            "duration_s": self.duration_s,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
