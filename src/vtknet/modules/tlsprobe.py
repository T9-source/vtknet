"""TLS ServerHello fingerprinting through a raw-socket handshake.

The ClientHello record is built by hand (deterministic bytes, no scapy TLS
API needed for building); the server reply is dissected with scapy's TLS
layers (needs ``cryptography`` installed alongside scapy). Phase-2 scope:
negotiated version + cipher suite. Certificate parsing comes in phase 3.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from scapy.all import Raw

from vtknet.core.converse import link_recv_bounded
from vtknet.core.engine import Engine
from vtknet.core.models import Evidence, Finding, Severity

log = logging.getLogger("vtknet.tlsprobe")

# shared by both the plain and the PQ probe: userspace TCP conversations


try:  # scapy TLS layers need ``cryptography`` at import time in some setups
    from scapy.layers.tls.handshake import TLSServerHello
    from scapy.layers.tls.record import TLS, TLSAlert

    _HAS_TLS = True
except Exception:  # noqa: BLE001 — import failure modes vary by scapy/env; degrade gracefully
    _HAS_TLS = False

DEFAULT_CIPHERS = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
    0x002F,  # RSA-AES128-SHA
]


# -- post-quantum hybrid ClientHello --------------------------------------
#
# Real clients increasingly offer X25519MLKEM768; the hybrid key_share pushes
# the ClientHello from ~300 to ~1400 bytes — past typical MTUs — and PKIC's
# multi-million-server scans documented origins that fail on *fragmented*
# ClientHellos (plus real breakage in middleboxes during 2026). The probe
# emits both shapes: a PQ-advertising hello, and a padded (forced-fragment)
# hello, then reads back which key_share group the server actually SELECTED.

# X25519MLKEM768 IANA "TLS Supported Groups" code point: 4588 DECIMAL.
# (4588 == 0x11EC — writing it as 0x4588 would advertise an unassigned
# group and make every server look post-quantum.)
MLKEM768_GROUP = 0x11EC
PQ_CIPHERS = [
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1301,  # TLS_AES_128_GCM_SHA256
    0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
]


def build_pq_client_hello_bytes(
    sni: str | None = None,
    ciphers: list[int] | None = None,
    rng: random.Random | None = None,
    force_fragment: bool = False,
) -> bytes:
    """ClientHello advertising the PQ-hybrid group (deterministic, v1 probe).

    ``force_fragment=True`` pads the hello (RFC 7685 padding extension) past
    1500 bytes so it crosses the TCP segment boundary exactly like real
    post-quantum ClientHellos do — the shape middleboxes choke on.
    """
    rng = rng or random.Random(0x5CA9)
    ciphers = ciphers if ciphers is not None else PQ_CIPHERS
    body = b"\x01\x00\x00\x00"
    body += b"\x03\x03"
    body += rng.getrandbits(256).to_bytes(32, "big")
    body += b"\x20" + rng.getrandbits(256).to_bytes(32, "big")
    suites = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body += len(suites).to_bytes(2, "big") + suites
    body += b"\x01\x00"
    exts = b""
    if sni:
        host = sni.encode("idna") if sni.encode("idna") else sni.encode("ascii")
        exts += _sni_extension(host)
    exts += b"\x00\x2b\x00\x03\x02\x03\x04"  # supported_versions: TLS 1.3
    # supported_groups: X25519MLKEM768 FIRST (client preference — real clients
    # list the hybrid group ahead of x25519), then classical x25519
    exts += b"\x00\x0a\x00\x08\x00\x06" + MLKEM768_GROUP.to_bytes(2, "big") + b"\x00\x1d"
    # key_share (0x0033): ONE 1216-byte X25519MLKEM768 client share —
    # ML-KEM-768 encapsulation key (1184B) FIRST, then the 32-byte x25519
    # share (reversed order "due to historical reasons", RFC 10024 §3.2).
    # This is the exact wire shape Chrome puts out; no separate x25519 entry.
    x25519_pub = rng.getrandbits(256).to_bytes(32, "big")
    mlkem_ek = rng.getrandbits(9472).to_bytes(1184, "big")
    hybrid_share = mlkem_ek + x25519_pub
    entry = MLKEM768_GROUP.to_bytes(2, "big") + len(hybrid_share).to_bytes(2, "big") + hybrid_share
    exts += b"\x00\x33" + len(entry).to_bytes(2, "big") + entry
    exts += b"\x00\x0d\x00\x06\x00\x04\x04\x03\x08\x04"  # signature_algorithms
    if force_fragment:
        pad_len = max(0, 1600 - (len(body) + len(exts) + 4 + 5))
        exts += b"\x00\x15" + pad_len.to_bytes(2, "big") + b"\x00" * pad_len
    body += len(exts).to_bytes(2, "big") + exts
    body = body[:1] + (len(body) - 4).to_bytes(3, "big") + body[4:]
    return b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body


def pq_tls_probe(
    engine: Engine,
    dst: str,
    port: int = 443,
    sni: str | None = None,
    force_fragment: bool = False,
    link_factory: Callable[[str, int], Any] | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Send one PQ-hybrid ClientHello and classify the reply.

    The ClientHello offers x25519 + X25519MLKEM768 (IANA code point 4588 =
    0x11EC) with a deterministic dummy key_share. On a ServerHello reply the
    server's SELECTED key_share group is read back from the record:

    - ``tls.pq.negotiated`` — server selected 0x11EC: a genuine
      post-quantum key-exchange path (info)
    - ``tls.pq.fallback`` — ServerHello came but a classical group was
      selected: the PQ hello survived the path, the server chose x25519
      (info)
    - ``tls.pq.alert`` — explicit rejection (low)
    - ``tls.pq.other`` / ``tls.pq.no-response`` — as before

    Limit, documented honestly: the client key_share carries deterministic
    dummy material, so no hybrid handshake can complete — group-selection
    and ServerHello/alert detection are valid; cipher agreement is not.
    Link reads are bounded by ``engine.cfg.timeout`` so silent-open servers
    cannot hang the probe.
    """
    if engine.cfg.dry_run:
        hello = build_pq_client_hello_bytes(sni=sni, force_fragment=force_fragment)
        log.info(
            "dry-run: would send a %d-byte PQ ClientHello to %s:%d (fragment_forced=%s)",
            len(hello),
            dst,
            port,
            force_fragment,
        )
        return [], {"sent": 0}

    factory = link_factory or _default_link_factory
    hello = build_pq_client_hello_bytes(sni=sni, force_fragment=force_fragment)
    payloads: list[bytes] = []
    primary: dict[str, Any] | None = None
    try:
        link = factory(dst, port)
    except Exception as exc:  # noqa: BLE001 — connect failures come in many shapes
        log.warning("could not open conversation to %s:%d: %s", dst, port, exc)
        return [_finding(dst, "tls.pq.no-response", port, sni, state="filtered")], {"sent": 0}
    try:
        link.send(hello)
        for _ in range(3):
            data = link_recv_bounded(link, engine.cfg.timeout)
            if not data:
                break  # timeout (link already closed by the bounded read) or EOF
            payloads.append(data)
            info = parse_server_hello(data)
            if info["kind"] in ("tls.serverhello", "tls.alert"):
                primary = info
                break
    finally:
        try:
            link.close()
        except Exception as exc:  # noqa: BLE001 — closing an already-dead socket is not fatal
            log.debug("link close: %s", exc)

    if primary is None:
        kind = "tls.pq.no-response" if not payloads else "tls.pq.other"
        findings = [_finding(dst, kind, port, sni, state=None if payloads else "filtered")]
        if payloads:
            findings[0].detail["note"] = "reply was not a ServerHello/alert"
            findings[0].evidence = [Evidence("packet_hex", payloads[0].hex(), "first reply bytes")]
    elif primary["kind"] == "tls.alert":
        findings = [
            Finding(
                module="tlsprobe",
                kind="tls.pq.alert",
                host=dst,
                port=port,
                state="open",
                severity=Severity.LOW,
                detail={
                    "port": port,
                    "sni": sni or dst,
                    "hello_bytes": len(hello),
                    "force_fragment": force_fragment,
                    **primary,
                },
                evidence=[Evidence("packet_hex", payloads[0].hex(), "server TLS record (PQ probe)")],
            )
        ]
    else:
        selected = parse_serverhello_selected_group(payloads[-1])
        confirmed = selected == MLKEM768_GROUP
        findings = [
            Finding(
                module="tlsprobe",
                kind="tls.pq.negotiated" if confirmed else "tls.pq.fallback",
                host=dst,
                port=port,
                state="open",
                severity=Severity.INFO,
                detail={
                    "port": port,
                    "sni": sni or dst,
                    "hello_bytes": len(hello),
                    "force_fragment": force_fragment,
                    "pq_selected_group": f"0x{selected:04x}" if selected is not None else None,
                    "pq_confirmed": confirmed,
                    **primary,
                },
                evidence=[Evidence("packet_hex", payloads[0].hex(), "server TLS record (PQ probe)")],
            )
        ]
    stats = {"sent": 1, "chunks": len(payloads)}
    log.info("pq-tls probe %s:%d -> %s", dst, port, findings[0].kind)
    return findings, stats


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


def parse_serverhello_selected_group(record_bytes: bytes) -> int | None:
    """Extract the key_share group the server SELECTED from a ServerHello.

    Pure bytes walk (no scapy TLS dependency). TLS 1.3 ServerHello framing:
    record(type 0x16) + handshake(type 0x02) + legacy_version(2) +
    random(32) + legacy_session_id<0..32> + cipher(2) + compression(1) +
    extensions; the key_share extension (0x0033) in a ServerHello holds
    exactly one entry: ``selected_group(2) + key_len(2) + key``. Returns
    ``None`` for alerts, TLS 1.2 hellos, or anything malformed — hostile
    bytes can only yield None, never an exception.
    """
    try:
        if len(record_bytes) < 43 or record_bytes[0] != 0x16:  # not a handshake record
            return None
        rec_len = int.from_bytes(record_bytes[3:5], "big")
        p = 5
        end = min(5 + rec_len, len(record_bytes))
        if p >= end or record_bytes[p] != 0x02:  # not a ServerHello
            return None
        p += 4  # handshake type + 3-byte length
        p += 2 + 32  # legacy_version + random
        sid_len = record_bytes[p]
        p += 1 + sid_len
        p += 2  # cipher_suite
        p += 1  # legacy_compression_method
        if p + 2 > end:
            return None
        ext_total = int.from_bytes(record_bytes[p : p + 2], "big")
        p += 2
        ext_end = min(p + ext_total, end)
        while p + 4 <= ext_end:
            etype = int.from_bytes(record_bytes[p : p + 2], "big")
            elen = int.from_bytes(record_bytes[p + 2 : p + 4], "big")
            if etype == 0x0033 and p + 6 <= ext_end:
                return int.from_bytes(record_bytes[p + 4 : p + 6], "big")
            p += 4 + elen
    except (IndexError, ValueError):
        return None
    return None


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


# -- live probe (TCP_client supersocket: correct seq/ack + retransmits) -----


def _default_link_factory(dst: str, port: int) -> Any:
    """Userspace TCP conversation via scapy's TCP_client automaton (root needed)."""
    from scapy.layers.inet import TCP_client  # local: pulls automaton machinery

    return TCP_client.tcplink(Raw, dst, port)


def tls_probe(
    engine: Engine,
    dst: str,
    port: int = 443,
    sni: str | None = None,
    link_factory: Callable[[str, int], Any] | None = None,
    pq: bool = False,
    force_fragment: bool = False,
) -> tuple[list[Finding], dict[str, int]]:
    """Open a TCP conversation to dst:port, send a ClientHello, classify the reply.

    The handshake runs over scapy's ``TCP_client`` automaton — SYN, ACKs and
    retransmissions handled by the supersocket instead of hand-tracked
    seq/ack. Pass ``link_factory`` to inject a fake supersocket (tests).
    With ``pq=True`` this becomes the post-quantum hybrid probe (v1).
    """
    if pq:
        return pq_tls_probe(
            engine,
            dst,
            port=port,
            sni=sni,
            force_fragment=force_fragment,
            link_factory=link_factory,
        )
    if engine.cfg.dry_run:
        hello = build_client_hello_bytes(sni=sni)
        log.info(
            "dry-run: would open a TCP conversation to %s:%d and send a %d-byte "
            "ClientHello (sni=%s)",
            dst,
            port,
            len(hello),
            sni or dst,
        )
        return [], {"sent": 0}

    factory = link_factory or _default_link_factory
    payloads: list[bytes] = []
    primary: dict[str, Any] | None = None
    try:
        link = factory(dst, port)
    except Exception as exc:  # noqa: BLE001 — connect failures come in many shapes
        log.warning("could not open conversation to %s:%d: %s", dst, port, exc)
        return [_finding(dst, "tls.no-response", port, sni, state="filtered")], {"sent": 0}
    try:
        link.send(build_client_hello_bytes(sni=sni))
        for _ in range(5):  # bounded flight collection: ServerHello + certificates
            chunk = link.recv()  # automaton ends itself on its internal timeouts
            if not chunk:
                break
            data = bytes(chunk)
            payloads.append(data)
            if primary is None:
                info = parse_server_hello(data)
                if info["kind"] not in ("tls.other", "tls.parse-error"):
                    primary = info
    finally:
        try:
            link.close()
        except Exception as exc:  # noqa: BLE001 — closing an already-dead socket is not fatal
            log.debug("link close: %s", exc)

    findings: list[Finding] = []
    if primary is not None:
        findings.append(
            Finding(
                module="tlsprobe",
                kind=primary["kind"],
                host=dst,
                port=port,
                state="open" if primary["kind"] == "tls.serverhello" else None,
                detail={"port": port, "sni": sni or dst, **primary},
                evidence=[Evidence("packet_hex", payloads[0].hex(), "server TLS record")],
            )
        )
    if not findings:
        findings.append(_finding(dst, "tls.no-data", port, sni, state="open"))
    findings.extend(certificate_findings(dst, port, extract_certificates(b"".join(payloads))))
    stats = {"sent": 1, "chunks": len(payloads)}
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
