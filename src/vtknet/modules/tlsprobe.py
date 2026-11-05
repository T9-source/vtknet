"""TLS ServerHello fingerprinting through a raw-socket handshake.

The ClientHello record is built by hand (deterministic bytes, no scapy TLS
API needed for building); the server reply is dissected with scapy's TLS
layers (needs ``cryptography`` installed alongside scapy). Phase-2 scope:
negotiated version + cipher suite. Certificate parsing comes in phase 3.
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timezone
from typing import Any

from scapy.all import IP, TCP

from vtknet.core.engine import Engine
from vtknet.core.models import Evidence, Finding, Severity

log = logging.getLogger("vtknet.tlsprobe")

try:  # scapy TLS layers need ``cryptography`` at import time in some setups
    from scapy.layers.tls.handshake import TLSServerHello
    from scapy.layers.tls.record import TLS, TLSAlert

    _HAS_TLS = True
except Exception:  # noqa: BLE001 — import failure modes vary by scapy/env; degrade gracefully
    _HAS_TLS = False

TCP_SYN, TCP_ACK = 0x02, 0x10

DEFAULT_CIPHERS = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
    0x002F,  # RSA-AES128-SHA
]


# -- building (pure, deterministic) ------------------------------------


def _sni_extension(hostname: bytes) -> bytes:
    name = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    lst = len(name).to_bytes(2, "big") + name
    return b"\x00\x00" + len(lst).to_bytes(2, "big") + lst


def build_client_hello_bytes(
    sni: str | None = None,
    ciphers: list[int] | None = None,
    rng: random.Random | None = None,
) -> bytes:
    """Hand-built TLS 1.2 ClientHello record — valid, fingerprintable, deterministic."""
    rng = rng or random.Random(0x5CA9)
    ciphers = ciphers if ciphers is not None else DEFAULT_CIPHERS
    body = b"\x01\x00\x00\x00"  # handshake type + length placeholder
    body += b"\x03\x03"  # client_version: TLS 1.2
    body += rng.getrandbits(256).to_bytes(32, "big")  # random
    body += b"\x20" + rng.getrandbits(256).to_bytes(32, "big")  # session id
    suites = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body += len(suites).to_bytes(2, "big") + suites
    body += b"\x01\x00"  # compression methods: null
    exts = b""
    if sni:
        host = sni.encode("idna") if sni.encode("idna") else sni.encode("ascii")
        exts += _sni_extension(host)
    exts += b"\x00\x2b\x00\x03\x02\x03\x04"  # supported_versions: TLS 1.3
    exts += b"\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17"  # supported_groups: x25519, p256
    exts += b"\x00\x0d\x00\x06\x00\x04\x04\x03\x08\x04"  # signature_algorithms
    body += len(exts).to_bytes(2, "big") + exts
    body = body[:1] + (len(body) - 4).to_bytes(3, "big") + body[4:]  # fix handshake length
    return b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body


# -- parsing -------------------------------------------------------------


def parse_server_hello(record_bytes: bytes) -> dict[str, Any]:
    """Dissect one TLS record; classify it as ServerHello / alert / other."""
    if not _HAS_TLS:
        raise RuntimeError("TLS parsing unavailable — install cryptography alongside scapy")
    try:
        parsed = TLS(record_bytes)
    except Exception as exc:  # noqa: BLE001 — hostile/garbled input must never crash the probe
        return {"kind": "tls.parse-error", "error": str(exc)}
    if parsed.haslayer(TLSServerHello):
        sh = parsed[TLSServerHello]
        ver = int(sh.version)
        return {
            "kind": "tls.serverhello",
            "version_int": f"0x{ver:04x}",
            "cipher": int(sh.cipher),
        }
    if parsed.haslayer(TLSAlert):
        return {"kind": "tls.alert", "description": int(parsed[TLSAlert].descr)}
    return {"kind": "tls.other"}


# -- certificate extraction (hand-parsed framing, cryptography for X.509) ---


def extract_certificates(payload: bytes) -> list[bytes]:
    """Pull DER certificates out of TLS Certificate handshake messages in a raw byte stream.

    Walks record framing (5-byte header) and the Certificate handshake body
    (3-byte chain length + 3-byte-per-cert entries) by hand — no dependency on
    scapy's TLS session machinery.
    """
    certs: list[bytes] = []
    i = 0
    while i + 5 <= len(payload):
        ctype = payload[i]
        rec_len = int.from_bytes(payload[i + 3 : i + 5], "big")
        rec = payload[i + 5 : i + 5 + rec_len]  # record header = 1+2+2 = 5 bytes
        i += 5 + rec_len
        if ctype != 22 or len(rec) < 4 or rec[0] != 11:  # handshake type 0x0b = certificate
            continue
        hlen = int.from_bytes(rec[1:4], "big")
        body = rec[4 : 4 + hlen]
        if len(body) < 3:
            continue
        chain = body[3 : 3 + int.from_bytes(body[0:3], "big")]
        j = 0
        while j + 3 <= len(chain):
            clen = int.from_bytes(chain[j : j + 3], "big")
            certs.append(chain[j + 3 : j + 3 + clen])
            j += 3 + clen
    return certs


def summarize_certificate(der: bytes) -> dict[str, Any]:
    """X.509 summary via cryptography: subject, issuer, expiry, SANs, self-signed."""
    from cryptography import x509  # local import: only needed when a cert is present

    cert = x509.load_der_x509_certificate(der)
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)[:8]
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "self_signed": cert.subject == cert.issuer,
        "sans": sans,
    }


def certificate_findings(dst: str, port: int, ders: list[bytes]) -> list[Finding]:
    """Turn extracted certificates into findings with expiry-based severity."""
    out: list[Finding] = []
    for der in ders:
        try:
            info = summarize_certificate(der)
        except Exception as exc:  # noqa: BLE001 — a malformed cert must never crash the probe
            log.warning("certificate parse error: %s", exc)
            continue
        if info["days_left"] < 0:
            kind, sev = "tls.cert.expired", Severity.HIGH
        elif info["days_left"] <= 30:
            kind, sev = "tls.cert.expiring", Severity.LOW
        else:
            kind, sev = "tls.certificate", Severity.INFO
        out.append(
            Finding(
                module="tlsprobe",
                kind=kind,
                host=dst,
                port=port,
                severity=sev,
                detail=info,
                evidence=[Evidence("certificate_der", der.hex(), "X.509 certificate (DER)")],
            )
        )
    return out


# -- live probe ------------------------------------------------------------


def tls_probe(
    engine: Engine, dst: str, port: int = 443, sni: str | None = None
) -> tuple[list[Finding], dict[str, int]]:
    """TCP-handshake to dst:port, send a ClientHello, parse the ServerHello."""
    if engine.cfg.dry_run:
        hello = build_client_hello_bytes(sni=sni)
        log.info(
            "dry-run: would TCP-handshake %s:%d then send a %d-byte ClientHello (sni=%s)",
            dst,
            port,
            len(hello),
            sni or dst,
        )
        return [], {"sent": 0}

    rng = random.Random()
    sport, seq = rng.randint(1024, 65535), rng.getrandbits(31)

    syn = IP(dst=dst) / TCP(sport=sport, dport=port, flags="S", seq=seq)
    synack = engine.send1(syn)
    if synack is None or not synack.haslayer(TCP):
        return [_finding(dst, "tls.no-response", port, sni, state="filtered")], {
            "sent": 1,
            "answered": 0,
        }
    if int(synack[TCP].flags) & (TCP_SYN | TCP_ACK) != (TCP_SYN | TCP_ACK):
        return [_finding(dst, "tls.no-synack", port, sni, state="filtered")], {
            "sent": 1,
            "answered": 1,
        }

    srv_seq = synack[TCP].seq + 1
    engine.send(IP(dst=dst) / TCP(sport=sport, dport=port, flags="A", seq=seq + 1, ack=srv_seq))

    hello = build_client_hello_bytes(sni=sni, rng=rng)
    probe = IP(dst=dst) / TCP(sport=sport, dport=port, flags="PA", seq=seq + 1, ack=srv_seq) / hello
    answered, _ = engine.send_recv([probe])

    findings: list[Finding] = []
    tls_replies = 0
    payloads: list[bytes] = []
    for _, rep in answered:
        payload = bytes(rep[TCP].payload) if rep.haslayer(TCP) else b""
        if not payload:
            continue
        payloads.append(payload)
        info = parse_server_hello(payload)
        if info["kind"] in ("tls.other", "tls.parse-error"):
            continue
        tls_replies += 1
        detail: dict[str, Any] = {"port": port, "sni": sni or dst, **info}
        findings.append(
            Finding(
                module="tlsprobe",
                kind=info["kind"],
                host=dst,
                port=port,
                state="open" if info["kind"] == "tls.serverhello" else None,
                detail=detail,
                evidence=[Evidence("packet_hex", payload.hex(), "server TLS record")],
            )
        )
        break  # the first classified record decides the primary finding

    if not findings:
        findings.append(_finding(dst, "tls.no-data", port, sni, state="open"))
    findings.extend(certificate_findings(dst, port, extract_certificates(b"".join(payloads))))
    stats = {"sent": 3, "answered": len(answered), "tls_payload_replies": tls_replies}
    log.info("tls probe %s:%d -> %s", dst, port, findings[0].kind)
    return findings, stats


def _finding(
    dst: str, kind: str, port: int, sni: str | None, state: str | None = None
) -> Finding:
    return Finding(
        module="tlsprobe",
        kind=kind,
        host=dst,
        port=port,
        state=state,
        detail={"port": port, "sni": sni or dst},
    )
