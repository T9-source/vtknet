"""ECH (Encrypted Client Hello, RFC 9849) probing.

Three detection surfaces, zero crypto required:

1. **DNS surface** — ECHConfigList is published in HTTPS/SVCB records
   (RFC 9460 §9): an HTTPS query for ``_443._tcp.example.com`` returning
   an ``ech`` key = the server advertises ECH configs (probe 1).
2. **GREASE surface** (RFC 9849 §6.2, ex draft-ietf-tls-esni §6.2): real
   browsers offer ECH even without configs (GREASE) to keep the extension
   observable. A GREASE-offering client that still completes the handshake
   proves the path does not kill odd-but-valid ClientHellos (probe 2).
3. **ech_required surface** — a server that REQUIRES ECH answers a
   non-ECH ClientHello with fatal alert **ech_required (121)** (IANA TLS
   Alerts via draft-ietf-tls-esni §11.2); seeing it = hard evidence of
   ECH enforcement (probe 3).

v1 limits (honest): no ECHConfig parsing/padding computation, no HPKE
encryption of an inner hello — those are phase 2. The GREASE shape is
streamlined (single extension, no outer/inner); signals are evidence-
backed (every reply recorded as hex). All reads are bounded by
``engine.cfg.timeout`` via ``link_recv_bounded``.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Callable
from typing import Any

from vtknet.core.converse import link_recv_bounded
from vtknet.core.engine import Engine
from vtknet.core.kinds import KindSpec, register_kind
from vtknet.core.models import Evidence, Finding, Severity

log = logging.getLogger("vtknet.ech")

# -- constants (primary-source pinned) ------------------------------------

ECH_EXT_TYPE = 0xFE0D  # encrypted_client_hello — TLS Extensions registry (RFC 9849 §11.1)
ALERT_ECH_REQUIRED = 121  # 0x79 — IANA TLS Alerts (draft-ietf-tls-esni §11.2 / RFC 9849)
ALERT_HANDSHAKE_FAILURE = 40
HTTPSPORT_PREFIX = "_443._tcp."


# -- building (pure, deterministic) ----------------------------------------


def build_grease_ech_extension(rng: random.Random) -> bytes:
    """A GREASE encrypted_client_hello extension (RFC 9849 §6.2).

    Body layout: version(2) + config_id(1) + length(2) + encapsulated blob.
    The blob is random bytes so no server can accept it — a compliant one
    ignores it (GREASE) or answers ech_required. The version uses the
    ?0?0 GREASE nibble convention.
    """
    blob_len = 16 + rng.getrandbits(4)  # small, bounded GREASE blob
    blob = rng.getrandbits(blob_len * 8).to_bytes(blob_len, "big")
    version = 0xA0A0 | rng.getrandbits(1)
    body = (
        version.to_bytes(2, "big")
        + rng.getrandbits(8).to_bytes(1, "big")  # config_id (ignored when GREASE)
        + len(blob).to_bytes(2, "big")
        + blob
    )
    return ECH_EXT_TYPE.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def build_grease_client_hello_bytes(
    sni: str | None = None,
    rng: random.Random | None = None,
) -> bytes:
    """TLS 1.2-style ClientHello carrying a GREASE ech extension (deterministic).

    Reuses the plain probe's hand-built framing and splices the GREASE ech
    in among the extensions — exactly how a real browser offering ECH
    without configs looks on the wire.
    """
    from vtknet.modules.tlsprobe import build_client_hello_bytes  # reuse framing

    rng = rng or random.Random(0x5CEC)
    base = build_client_hello_bytes(sni=sni, rng=rng)
    grease = build_grease_ech_extension(rng)
    # walk the fixed ClientHello structure forward to the extensions-length field:
    # record(5) + hs-hdr(4) + version(2) + random(32) | sid_len(1) + sid |
    # suites_len(2) + suites | compression(2) | extensions_len(2) + extensions
    p = 43
    sid_len = base[p]
    p += 1 + sid_len
    suites_len = int.from_bytes(base[p : p + 2], "big")
    p += 2 + suites_len + 2  # suites block + compression methods (01 00)
    ext_len_off = p
    ext_len = int.from_bytes(base[ext_len_off : ext_len_off + 2], "big")
    grow = len(grease)
    # extensions are the last element of the record: append at the end and
    # bump the three enclosing lengths (extensions, handshake, record)
    out = bytearray(base)
    out[ext_len_off : ext_len_off + 2] = (ext_len + grow).to_bytes(2, "big")
    out[6:9] = (int.from_bytes(base[6:9], "big") + grow).to_bytes(3, "big")
    out[3:5] = (int.from_bytes(base[3:5], "big") + grow).to_bytes(2, "big")
    out += grease
    return bytes(out)


# -- parsing ----------------------------------------------------------------


def classify_reply(record_bytes: bytes) -> dict[str, Any]:
    """Classify a reply record for the ECH probes (pure, hostile-safe).

    ``tls.serverhello`` / ``tls.alert.ech-required`` /
    ``tls.alert.handshake-failure`` / ``tls.alert.other`` / ``tls.other``.
    Malformed bytes can only yield a kind, never an exception.
    """
    try:
        if len(record_bytes) >= 7 and record_bytes[0] == 0x15:  # alert record
            descr = record_bytes[6]
            if descr == ALERT_ECH_REQUIRED:
                return {"kind": "tls.alert.ech-required", "level": record_bytes[5]}
            if descr == ALERT_HANDSHAKE_FAILURE:
                return {"kind": "tls.alert.handshake-failure", "level": record_bytes[5]}
            return {"kind": "tls.alert.other", "description": descr}
        if len(record_bytes) > 5 and record_bytes[0] == 0x16:  # handshake record
            try:
                from vtknet.modules.tlsprobe import parse_server_hello

                info = parse_server_hello(record_bytes)
                if info.get("kind") == "tls.serverhello":
                    return info
            except Exception as exc:  # noqa: BLE001 — degrade to the framing check
                log.debug("tls layer parse unavailable: %s", exc)
            return {"kind": "tls.serverhello"}
    except (IndexError, ValueError):
        pass
    return {"kind": "tls.other"}


# -- DNS surface ------------------------------------------------------------


def parse_https_record_ech(rdata: str) -> dict[str, Any] | None:
    """Extract the ech key (SVCB key 5) from an HTTPS/SVCB presentation record.

    Presentation form: ``1 . alpn=h2 ech=<base64...>`` — returns
    ``{"ech_present": True, "config_b64": ...}`` or None when absent.
    """
    ech_value: str | None = None
    for param in rdata.split():
        if param.lower().startswith("ech="):
            ech_value = param[4:]
    if not ech_value:
        return None
    return {"ech_present": True, "config_b64": ech_value}


def dns_ech_check(engine: Engine, hostname: str) -> Finding:
    """Probe 1: does the zone publish an ECHConfigList for this host?"""
    from scapy.all import DNS, DNSQR, IP, UDP  # local: only needed for the live query

    from vtknet.modules.dnsprobe import extract_answers  # reuse the hardened extractor

    qname = HTTPSPORT_PREFIX + hostname
    pkt = (
        IP(dst="1.1.1.1")
        / UDP(sport=53531, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype="HTTPS"))
    )
    answered, _ = engine.send_recv([pkt])
    if not answered:
        return Finding(
            module="echprobe",
            kind="ech.dns.no-record",
            host=hostname,
            detail={"qname": qname, "note": "no HTTPS record reply from resolver"},
        )
    answers = extract_answers(answered[0][1])
    for rdata in answers:
        info = parse_https_record_ech(rdata)
        if info:
            return Finding(
                module="echprobe",
                kind="ech.dns.config-found",
                host=hostname,
                detail={"qname": qname, **info},
                evidence=[Evidence("packet_hex", bytes(answered[0][1]).hex(), "HTTPS RR reply")],
            )
    return Finding(
        module="echprobe",
        kind="ech.dns.no-record",
        host=hostname,
        detail={"qname": qname, "answers": answers[:4]},
    )


# -- live probes --------------------------------------------------------------


def _default_link_factory(dst: str, port: int) -> Any:
    from scapy.all import Raw  # local: only needed when a live link is built
    from scapy.layers.inet import TCP_client

    return TCP_client.tcplink(Raw, dst, port)


def _finding(dst: str, kind: str, port: int, detail: dict[str, Any] | None = None) -> Finding:
    return Finding(module="echprobe", kind=kind, host=dst, port=port, detail=detail or {})


def greased_ech_probe(
    engine: Engine,
    dst: str,
    port: int = 443,
    sni: str | None = None,
    link_factory: Callable[[str, int], Any] | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Probes 2+3 in one conversation: GREASE hello in, classify what returns.

    - ServerHello back              → ``ech.path.tolerant`` (GREASE accepted)
    - alert ech_required (121)      → ``ech.enforced`` (HIGH — ECH is mandatory)
    - alert handshake_failure (40)  → ``ech.path.intolerant`` (MEDIUM —
      path or server kills odd-but-valid hellos; a middlebox signal)
    - other/none                    → ``ech.no-signal``
    """
    if engine.cfg.dry_run:
        hello = build_grease_client_hello_bytes(sni=sni)
        log.info(
            "dry-run: would send a %d-byte GREASE-ECH ClientHello to %s:%d",
            len(hello),
            dst,
            port,
        )
        return [], {"sent": 0}

    factory = link_factory or _default_link_factory
    try:
        link = factory(dst, port)
    except Exception as exc:  # noqa: BLE001 — connect failures come in many shapes
        log.warning("could not open conversation to %s:%d: %s", dst, port, exc)
        return [_finding(dst, "ech.no-signal", port, {"note": "no connection"})], {"sent": 0}

    reply = b""
    try:
        link.send(build_grease_client_hello_bytes(sni=sni))
        for _ in range(3):
            data = link_recv_bounded(link, engine.cfg.timeout)
            if not data:
                break
            reply = data
            if classify_reply(data)["kind"] != "tls.other":
                break
    finally:
        try:
            link.close()
        except Exception as exc:  # noqa: BLE001 — closing an already-dead socket is not fatal
            log.debug("link close: %s", exc)

    if not reply:
        findings = [_finding(dst, "ech.no-signal", port, {"note": "no reply"})]
    else:
        info = classify_reply(reply)
        kind_map = {
            "tls.serverhello": ("ech.path.tolerant", Severity.INFO),
            "tls.alert.ech-required": ("ech.enforced", Severity.HIGH),
            "tls.alert.handshake-failure": ("ech.path.intolerant", Severity.MEDIUM),
        }
        kind, sev = kind_map.get(info["kind"], ("ech.no-signal", Severity.INFO))
        findings = [
            Finding(
                module="echprobe",
                kind=kind,
                host=dst,
                port=port,
                severity=sev,
                detail={"port": port, "sni": sni or dst, **info},
                evidence=[
                    Evidence("packet_hex", reply.hex(), f"reply to GREASE-ECH hello ({dst}:{port})")
                ],
            )
        ]
    log.info("ech probe %s:%d -> %s", dst, port, findings[0].kind)
    return findings, {"sent": 1, "chunks": 1 if reply else 0}


def ech_probe(
    engine: Engine,
    dst: str,
    port: int = 443,
    sni: str | None = None,
    link_factory: Callable[[str, int], Any] | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Full v1 ECH surface: DNS config lookup + one GREASE conversation."""
    if engine.cfg.dry_run:
        log.info("dry-run: ech surface check for %s:%d (dns + greased hello)", dst, port)
        return [], {"sent": 0}
    findings = [dns_ech_check(engine, dst)]
    greased, stats = greased_ech_probe(engine, dst, port=port, sni=sni, link_factory=link_factory)
    findings.extend(greased)
    return findings, {**stats, "probes": 2}


# -- kinds registry -----------------------------------------------------------

for _kind, _meaning, _sev in (
    ("ech.dns.config-found", "Zone publishes an ECHConfigList in HTTPS/SVCB", "info"),
    ("ech.dns.no-record", "No HTTPS/SVCB ECH config found for the host", "info"),
    ("ech.path.tolerant", "Server answered ServerHello to a GREASE-ECH hello", "info"),
    ("ech.enforced", "Server answered fatal ech_required (121) — ECH is mandatory", "high"),
    ("ech.path.intolerant", "Handshake-failure to the GREASE hello — path/server intolerance", "medium"),
    ("ech.no-signal", "No ECH signal observed (no reply / unclassifiable)", "info"),
):
    register_kind(KindSpec(_kind, "echprobe", _meaning, _sev))
