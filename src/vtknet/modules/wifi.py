"""802.11 monitoring: deauth-storm, evil-twin and rogue-AP detection.

Works live against a monitor-mode interface or offline against a captured
pcap (``--offline``), which makes every detector unit-testable without any
hardware. The frame builders here exist to produce test fixtures for the
detectors — replay them only inside your own lab.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeResp, RadioTap
from scapy.packet import Packet

from vtknet.core.capture import Capture, CaptureConfig
from vtknet.core.models import Finding, Severity

log = logging.getLogger("vtknet.wifi")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


# -- fixture builders (for detector tests / lab replays) -------------------


def deauth_frame(ap_mac: str, client_mac: str = BROADCAST_MAC, reason: int = 7) -> Packet:
    """Management frame subtype 12 — use to validate your own deauth detector."""
    return (
        RadioTap()
        / Dot11(type=0, subtype=12, addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
        / Dot11Deauth(reason=reason)
    )


def beacon_frame(ssid: str, bssid: str, channel: int = 6) -> Packet:
    """Beacon frame fixture for evil-twin / rogue-AP detector tests."""
    return (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1=BROADCAST_MAC, addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )


# -- classification (pure, testable offline) --------------------------------


def _elt_walk(pkt: Packet) -> list[Dot11Elt]:
    out: list[Dot11Elt] = []
    cur = pkt.getlayer(Dot11Elt)
    while cur is not None and isinstance(cur, Dot11Elt):
        out.append(cur)
        cur = cur.payload
    return out


def _ap_info(pkt: Packet) -> dict[str, Any]:
    bssid = pkt[Dot11].addr3 or pkt[Dot11].addr2 or "?"
    ssid, channel = "", None
    for elt in _elt_walk(pkt):
        if int(elt.ID) == 0:
            ssid = bytes(elt.info).decode("utf-8", errors="replace")
        elif int(elt.ID) == 3 and elt.info:
            channel = elt.info[0]
    return {"bssid": bssid, "ssid": ssid, "channel": channel}


def classify_frame(pkt: Packet) -> dict[str, Any] | None:
    """Classify an 802.11 frame of interest: deauth / beacon / probe-resp."""
    if pkt.haslayer(Dot11Deauth):
        d = pkt[Dot11Deauth]
        return {
            "type": "deauth",
            "reason": int(d.reason),
            "from": pkt[Dot11].addr2 or "?",
            "target": pkt[Dot11].addr1 or "?",
        }
    if pkt.haslayer(Dot11Beacon):
        return {"type": "beacon", **_ap_info(pkt)}
    if pkt.haslayer(Dot11ProbeResp):
        return {"type": "probe-resp", **_ap_info(pkt)}
    return None


def analyze_frames(
    pkts: list[Packet],
    *,
    known_ssid: str | None = None,
    known_bssids: list[str] | None = None,
    deauth_threshold: int = 3,
) -> tuple[list[Finding], dict[str, int]]:
    """Detector pass over a list of 802.11 frames.

    Findings:
    - ``wifi.deauth.storm``: >= threshold deauth frames from one sender (HIGH)
    - ``wifi.rogue-ap``: known SSID advertised from an unknown BSSID (HIGH)
    - ``wifi.evil-twin``: one SSID advertised from multiple BSSIDs (MEDIUM)
    """
    deauths: dict[str, list[str]] = defaultdict(list)
    aps: dict[str, set[str]] = defaultdict(set)
    deauth_count = beacon_count = 0

    for pkt in pkts:
        info = classify_frame(pkt)
        if info is None:
            continue
        if info["type"] == "deauth":
            deauths[info["from"]].append(info["target"])
            deauth_count += 1
        else:
            aps[info["ssid"]].add(info["bssid"])
            beacon_count += 1

    findings: list[Finding] = []
    for sender, targets in sorted(deauths.items()):
        if len(targets) >= deauth_threshold:
            findings.append(
                Finding(
                    module="wifi",
                    kind="wifi.deauth.storm",
                    host=sender,
                    severity=Severity.HIGH,
                    detail={
                        "frames": len(targets),
                        "targets": sorted(set(targets))[:10],
                        "threshold": deauth_threshold,
                    },
                )
            )

    known = {b.lower() for b in (known_bssids or [])}
    for ssid, bssids in sorted(aps.items()):
        if not ssid:
            continue
        if known_ssid is not None and ssid == known_ssid:
            unknown = sorted(b for b in bssids if b.lower() not in known)
            if unknown:
                findings.append(
                    Finding(
                        module="wifi",
                        kind="wifi.rogue-ap",
                        host=ssid,
                        severity=Severity.HIGH,
                        detail={"ssid": ssid, "unknown_bssids": unknown, "known": sorted(known)},
                    )
                )
        elif len(bssids) > 1:
            findings.append(
                Finding(
                    module="wifi",
                    kind="wifi.evil-twin",
                    host=ssid,
                    severity=Severity.MEDIUM,
                    detail={"ssid": ssid, "bssids": sorted(bssids)},
                )
            )

    stats = {
        "frames": len(pkts),
        "deauth_frames": deauth_count,
        "beacon_frames": beacon_count,
        "distinct_ssids": len(aps),
    }
    log.info("wifi analysis: %s", stats)
    return findings, stats


# -- capture-backed entry points -------------------------------------------


def monitor(
    iface: str,
    *,
    timeout: float = 10.0,
    known_ssid: str | None = None,
    known_bssids: list[str] | None = None,
    deauth_threshold: int = 3,
) -> tuple[list[Finding], dict[str, Any]]:
    """Live analysis on a monitor-mode interface (root required)."""
    cap = Capture(
        CaptureConfig(iface=iface, timeout=timeout, max_packets=50000, promisc=True)
    )
    cap.start()
    cap.wait(timeout=timeout + 5.0)
    pkts = cap.stop()
    findings, stats = analyze_frames(
        pkts,
        known_ssid=known_ssid,
        known_bssids=known_bssids,
        deauth_threshold=deauth_threshold,
    )
    stats["capture"] = cap.stats()
    return findings, stats


def analyze_offline(
    path: str,
    *,
    known_ssid: str | None = None,
    known_bssids: list[str] | None = None,
    deauth_threshold: int = 3,
) -> tuple[list[Finding], dict[str, Any]]:
    """Analyze a captured wifi pcap — no root, no hardware (used by CI tests)."""
    cap = Capture(CaptureConfig(offline=path, max_packets=50000))
    cap.start()
    cap.wait(timeout=15.0)
    pkts = cap.stop()
    findings, stats = analyze_frames(
        pkts,
        known_ssid=known_ssid,
        known_bssids=known_bssids,
        deauth_threshold=deauth_threshold,
    )
    stats["capture"] = cap.stats()
    return findings, stats
