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

log = logging.getLogger("vtknet.inspect")


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
    """Best-effort decode of wire bytes: Ether framing first, then IP/IPv6 fallback."""
    pkt = Ether(data)
    names = {l.__name__ for l in pkt.layers()}
    if names - {"Ether", "Raw"}:  # something beyond the bare frame got decoded
        return pkt
    nibble = data[0] >> 4 if data else 0
    if nibble == 4:
        return IP(data)
    if nibble == 6:
        return IPv6(data)
    return pkt


def _ts_iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


def pcap_summary(path: str) -> dict[str, Any]:
    """One-pass streaming summary of a pcap (memory-bounded: counters only).

    Never loads the whole file — pair with the streaming capture in
    ``core.capture`` for captures of any size.
    """
    from scapy.utils import PcapReader  # local: generator-scoped file handle

    total = 0
    protocols: Counter = Counter()
    talkers: Counter = Counter()
    conversations: Counter = Counter()
    first_ts = last_ts = None
    with PcapReader(path) as reader:
        for pkt in reader:
            total += 1
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
                talkers[f"{src} -> {dst}"] += 1
                if pkt.haslayer(TCP):
                    conversations[f"TCP {src}:{pkt[TCP].sport} > {dst}:{pkt[TCP].dport}"] += 1
                elif pkt.haslayer(UDP):
                    conversations[f"UDP {src}:{pkt[UDP].sport} > {dst}:{pkt[UDP].dport}"] += 1
    duration = round(last_ts - first_ts, 3) if total > 1 else 0.0
    return {
        "packets": total,
        "started": _ts_iso(first_ts),
        "ended": _ts_iso(last_ts),
        "duration_s": duration,
        "layers_seen": dict(protocols.most_common(10)),
        "top_talkers": talkers.most_common(10),
        "top_conversations": conversations.most_common(10),
    }
