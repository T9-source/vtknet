"""Evidence reading: decode hex/pcap bytes back into layers, and streaming pcap stats.

No traffic, no root — this is the human-facing side of the evidence model:
every hex blob saved by the toolkit can be turned back into readable layers.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from scapy.all import IP, TCP, UDP, Ether, IPv6
from scapy.packet import Packet

from vtknet.core.capture import iter_pcap_safe

log = logging.getLogger("vtknet.inspect")

# memory caps: a hostile pcap with millions of unique conversations must not OOM us
MAX_UNIQUE_KEYS = 50_000


def parse_evidence(text: str) -> bytes:
    """Parse a hex string (optional spaces, colons, dashes, 0x prefix) into bytes."""
    s = "".join(text.split()).replace(":", "").replace("-", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if not s:
        raise ValueError("empty evidence string")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError("evidence is not valid hex") from exc


def decode_bytes(data: bytes) -> Packet:
    """Best-effort decode of hostile wire bytes: Ether framing, then IP/IPv6 fallback.

    Never raises on garbage — the worst case is an opaque Raw packet.
    """
    from scapy.all import Raw

    def _try(cls) -> Packet | None:
        try:
            return cls(data)
        except Exception:  # noqa: BLE001 — dissection of hostile bytes may explode
            return None

    pkt = _try(Ether)
    if pkt is not None and {l.__name__ for l in pkt.layers()} - {"Ether", "Raw"}:
        return pkt  # something beyond the bare frame got decoded
    nibble = data[0] >> 4 if data else 0
    if nibble == 4:
        fallback = _try(IP)
        if fallback is not None:
            return fallback
    elif nibble == 6:
        fallback = _try(IPv6)
        if fallback is not None:
            return fallback
    return Raw(data)


def _ts_iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


def pcap_summary(path: str) -> dict[str, Any]:
    """One-pass streaming summary of a pcap (memory-bounded, hostile-input safe).

    Never loads the whole file; malformed records are skipped and counted;
    unique-key counters are capped (``MAX_UNIQUE_KEYS``) so a pcap with
    millions of forged conversations cannot exhaust memory.
    """
    total = 0
    junk = 0
    truncated = False
    iter_stats: dict = {}
    protocols: Counter = Counter()
    talkers: Counter = Counter()
    conversations: Counter = Counter()
    first_ts = last_ts = None
    try:
        for pkt in iter_pcap_safe(path, stats=iter_stats):
            total += 1
            # hostile-capture artifact: scapy leniently dissects garbage records
            # into opaque frames — they pollute stats with fabricated fields
            if {l.__name__ for l in pkt.layers()} <= {"Ether", "Raw"}:
                junk += 1
                continue
            ts = float(pkt.time)
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
            for layer in pkt.layers():
                protocols[layer.__name__] += 1
            src = dst = None
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            if src and dst:
                if len(talkers) < MAX_UNIQUE_KEYS:
                    talkers[f"{src} -> {dst}"] += 1
                else:
                    truncated = True
                if pkt.haslayer(TCP) and len(conversations) < MAX_UNIQUE_KEYS:
                    conversations[f"TCP {src}:{pkt[TCP].sport} > {dst}:{pkt[TCP].dport}"] += 1
                    truncated = truncated or len(conversations) >= MAX_UNIQUE_KEYS
                elif pkt.haslayer(UDP) and len(conversations) < MAX_UNIQUE_KEYS:
                    conversations[f"UDP {src}:{pkt[UDP].sport} > {dst}:{pkt[UDP].dport}"] += 1
                    truncated = truncated or len(conversations) >= MAX_UNIQUE_KEYS
    except ValueError:
        raise  # already a clear toolkit error (from iter_pcap_safe) — no double wrap
    except Exception as exc:
        raise ValueError(f"unreadable pcap ({path}): {exc}") from exc
    duration = round(last_ts - first_ts, 3) if total > 1 else 0.0
    return {
        "packets": total,
        "junk_suspect": junk,
        "malformed": iter_stats.get("malformed", 0),
        "truncated": truncated,
        "started": _ts_iso(first_ts),
        "ended": _ts_iso(last_ts),
        "duration_s": duration,
        "layers_seen": dict(protocols.most_common(10)),
        "top_talkers": talkers.most_common(10),
        "top_conversations": conversations.most_common(10),
    }
