"""Deep evidence verification — beyond the hash, into the claim.

``vtk verify --deep`` walks evidence whose bytes can re-prove the claim:

- ``packet_hex`` evidence of a ``port.open`` finding is decoded back into
  a packet; the claim holds when the reply TCP flags actually carry SYN-ACK
  (0x12) — the same classifier the scanner used on the wire;
- ``packet_hex`` evidence of ``host.alive`` must decode to an ICMP echo
  reply (type 0);
- certificate evidence (``certificate_der``) is re-parsed via cryptography
  and the expiry claim is re-derived;
- anything else (or undecodable bytes) is reported as ``verify.deep.skipped``
  — deep verification is additive, never a false-fail generator.

This closes the loop the shallow verifier opened: hashes prove the bytes
did not change; deep checks prove the bytes still *mean what we said*.
"""

from __future__ import annotations

import logging
from typing import Any

from vtknet.core.kinds import get_kind
from vtknet.core.models import Finding, Severity
from vtknet.core.verify import verify_report

log = logging.getLogger("vtknet.verify-deep")


def _deep_check_one(f: dict[str, Any], ev: dict[str, Any]) -> dict[str, Any] | None:
    """Re-derive one evidence's claim from its own bytes (None = not deep-checkable)."""
    kind = str(f.get("kind", ""))
    ev_kind = str(ev.get("kind", ""))
    data = ev.get("data", "")

    if ev_kind == "certificate_der":
        return _check_certificate(kind, data)

    if ev_kind != "packet_hex":
        if kind in ("port.open", "host.alive", "tls.cert.expired", "tls.cert.expiring", "tls.certificate"):
            return {
                "kind": "verify.deep.skipped",
                "note": f"evidence kind {ev_kind!r} is not deep-checkable for this claim",
            }
        return None
    try:
        raw = bytes.fromhex(data)
    except ValueError:
        return {"kind": "verify.deep.skipped", "note": "evidence is not valid hex"}

    if kind == "port.open":
        return _check_port_open(raw)
    if kind == "host.alive":
        return _check_icmp_reply(raw)
    return None


def _check_port_open(raw: bytes) -> dict[str, Any]:
    """A port.open proof must be a TCP reply with SYN+ACK set (scanner classifier)."""
    if len(raw) < 34:  # Ether(14) + IP(20) minimum for a TCP reply frame
        return {"kind": "verify.deep.skipped", "note": "frame too short for TCP/IP"}
    # locate the TCP header: assume Ether+IPv4 (the scanner stores reply frames)
    if raw[0:1] == b"\x00" and raw[12:14] == b"\x08\x00":  # EtherTYPE IPv4
        ihl = (raw[14] & 0x0F) * 4
        tcp_off = 14 + ihl
    elif (raw[0] >> 4) == 4:  # raw IP
        ihl = (raw[0] & 0x0F) * 4
        tcp_off = ihl
    else:
        return {"kind": "verify.deep.skipped", "note": "not an IPv4 frame"}
    if len(raw) < tcp_off + 14:
        return {"kind": "verify.deep.skipped", "note": "no TCP header in frame"}
    flags = raw[tcp_off + 13]
    if flags & 0x12 == 0x12:  # SYN+ACK
        return {"kind": "verify.deep.holds", "note": "reply flags carry SYN+ACK", "flags": f"0x{flags:02x}"}
    if flags & 0x04:  # RST
        return {
            "kind": "verify.deep.contradicts",
            "note": "reply is a RST — the port.open claim is contradicted by its own evidence",
            "flags": f"0x{flags:02x}",
        }
    return {"kind": "verify.deep.skipped", "note": f"flags 0x{flags:02x} neither confirm nor contradict"}


def _check_icmp_reply(raw: bytes) -> dict[str, Any]:
    """A host.alive proof must decode to an ICMP echo reply (type 0)."""
    icmp_off = None
    if raw[0:1] == b"\x00" and raw[12:14] == b"\x08\x00":
        ihl = (raw[14] & 0x0F) * 4
        icmp_off = 14 + ihl
    elif (raw[0] >> 4) == 4:
        ihl = (raw[0] & 0x0F) * 4
        proto = raw[9]
        if proto != 1:
            return {"kind": "verify.deep.skipped", "note": f"IP proto {proto}, not ICMP"}
        icmp_off = ihl
    if icmp_off is None or len(raw) < icmp_off + 1:
        return {"kind": "verify.deep.skipped", "note": "no ICMP header"}
    itype = raw[icmp_off]
    if itype == 0:
        return {"kind": "verify.deep.holds", "note": "ICMP echo reply confirmed"}
    if itype == 8:
        return {
            "kind": "verify.deep.contradicts",
            "note": "evidence is an echo REQUEST, not a reply — alive claim unsupported",
        }
    return {"kind": "verify.deep.skipped", "note": f"ICMP type {itype}"}


def _check_certificate(kind: str, hexdata: str) -> dict[str, Any] | None:
    """Re-derive the expiry claim of a certificate evidence."""
    if kind not in ("tls.cert.expired", "tls.cert.expiring", "tls.certificate"):
        return None
    try:
        from datetime import datetime, timezone

        from cryptography import x509

        der = bytes.fromhex(hexdata)
        cert = x509.load_der_x509_certificate(der)
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
    except Exception as exc:  # noqa: BLE001 — a malformed cert is a skip, not a crash
        return {"kind": "verify.deep.skipped", "note": f"certificate re-parse failed: {exc}"}
    claimed_expired = kind == "tls.cert.expired"
    actually_expired = days_left < 0
    if claimed_expired == actually_expired:
        return {"kind": "verify.deep.holds", "note": f"expiry claim holds (days_left={days_left})"}
    return {
        "kind": "verify.deep.contradicts",
        "note": f"expiry claim contradicted (kind={kind}, days_left={days_left})",
    }


def verify_report_deep(report: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    """Shallow verify (hashes + kinds) then re-derive every deep-checkable claim."""
    findings, stats = verify_report(report)
    holds = contradicts = skipped = 0
    for f in report.get("findings", []):
        if get_kind(str(f.get("kind", ""))) is None and str(f.get("kind", "")).startswith(
            ("eval.", "ech.")
        ):
            continue  # unregistered kinds already flagged by the shallow pass
        for ev in f.get("evidence", []):
            if not isinstance(ev, dict):
                continue
            result = _deep_check_one(f, ev)
            if result is None:
                continue
            rkind = result.pop("kind")
            sev = (
                Severity.MEDIUM
                if rkind == "verify.deep.contradicts"
                else Severity.INFO
            )
            findings.append(
                Finding(
                    module="verify",
                    kind=rkind,
                    host=str(f.get("host", "-")),
                    severity=sev,
                    detail={"finding_id": f.get("id", "?"), "claim_kind": f.get("kind", ""), **result},
                )
            )
            if rkind == "verify.deep.holds":
                holds += 1
            elif rkind == "verify.deep.contradicts":
                contradicts += 1
            else:
                skipped += 1
    stats.update({"deep_holds": holds, "deep_contradicts": contradicts, "deep_skipped": skipped})
    log.info(
        "deep verify: %d holds, %d contradict(s), %d skipped", holds, contradicts, skipped
    )
    return findings, stats
