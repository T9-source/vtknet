"""Central registry of finding kinds — one meaning, default severity, reference.

Every module labels its claims with a ``kind``; this registry is the single
place that defines what each label means and its default severity. It backs
``vtk kinds`` (human table), ``vtk kinds --schema`` (JSON Schema for the
findings payload) and keeps module/plugin labels from drifting apart.

Taxonomy contract (OSV-style, per https://ossf.github.io/osv-schema/):
- ``SCHEMA_VERSION`` follows SemVer; MINOR/PATCH bumps are additive-only —
  new kinds or new optional fields never change the meaning of old ones;
- consumers that know 1.2.0 can safely read 1.3.0 by ignoring unknown kinds;
- removing or re-meaning a kind requires a MAJOR bump (never done so far).
"""

from __future__ import annotations

from dataclasses import dataclass

SCHEMA_VERSION = "1.1.0"  # SemVer; additive-only evolution (see module docstring)


@dataclass(frozen=True)
class KindSpec:
    kind: str
    module: str
    meaning: str
    severity: str  # default severity as emitted by the producing module
    reference: str = ""


KINDS: dict[str, KindSpec] = {
    # -- recon ---------------------------------------------------------------
    "host.alive": KindSpec("host.alive", "recon", "Host answered an ICMP echo", "info"),
    "host.arp-entry": KindSpec(
        "host.arp-entry", "recon", "Host answered an ARP who-has (L2 presence)", "info"
    ),
    # -- scanner ---------------------------------------------------------------
    "port.open": KindSpec(
        "port.open", "scanner", "TCP port accepted a connection-classifying probe", "info"
    ),
    # -- banner ---------------------------------------------------------------
    "banner.grabbed": KindSpec(
        "banner.grabbed",
        "banner",
        "Service spoke first; first bytes captured as evidence",
        "info",
    ),
    "banner.no-data": KindSpec(
        "banner.no-data",
        "banner",
        "Connection opened but the service waits for the client to speak",
        "info",
    ),
    "banner.no-connection": KindSpec(
        "banner.no-connection", "banner", "TCP conversation could not be opened", "info"
    ),
    # -- tlsprobe ---------------------------------------------------------------
    "tls.serverhello": KindSpec(
        "tls.serverhello", "tlsprobe", "ServerHello received: version + cipher", "info"
    ),
    "tls.alert": KindSpec("tls.alert", "tlsprobe", "Server answered with a TLS alert", "info"),
    "tls.other": KindSpec(
        "tls.other", "tlsprobe", "Reply was a TLS record but not a ServerHello", "info"
    ),
    "tls.parse-error": KindSpec(
        "tls.parse-error", "tlsprobe", "Reply bytes could not be parsed as TLS", "info"
    ),
    "tls.no-response": KindSpec(
        "tls.no-response", "tlsprobe", "No reply to the ClientHello (filtered?)", "info"
    ),
    "tls.no-data": KindSpec(
        "tls.no-data", "tlsprobe", "Connection opened but no TLS record arrived", "info"
    ),
    "tls.certificate": KindSpec(
        "tls.certificate", "tlsprobe", "X.509 certificate audited (healthy)", "info"
    ),
    "tls.cert.expiring": KindSpec(
        "tls.cert.expiring",
        "tlsprobe",
        "Certificate expires within 30 days",
        "low",
        "CA/Browser Forum Baseline Requirements",
    ),
    "tls.cert.expired": KindSpec(
        "tls.cert.expired", "tlsprobe", "Certificate is already expired", "high"
    ),
    "tls.pq.negotiated": KindSpec(
        "tls.pq.negotiated",
        "tlsprobe",
        "Server selected X25519MLKEM768 (0x11EC) in its key_share — real PQ path",
        "info",
        "RFC 10024 (hybrid ML-KEM key agreement for TLS 1.3)",
    ),
    "tls.pq.fallback": KindSpec(
        "tls.pq.fallback",
        "tlsprobe",
        "ServerHello returned but a classical group was selected — PQ hello survived the path",
        "info",
    ),
    "tls.pq.alert": KindSpec(
        "tls.pq.alert",
        "tlsprobe",
        "Server rejected the PQ ClientHello with a TLS alert",
        "low",
    ),
    "tls.pq.other": KindSpec(
        "tls.pq.other", "tlsprobe", "Reply to the PQ ClientHello was neither ServerHello nor alert", "info"
    ),
    "tls.pq.no-response": KindSpec(
        "tls.pq.no-response", "tlsprobe", "No reply to the PQ ClientHello (filtered?)", "info"
    ),
    # -- quicprobe ---------------------------------------------------------------
    "quic.version-negotiation": KindSpec(
        "quic.version-negotiation",
        "quicprobe",
        "QUIC endpoint answered Version Negotiation (RFC 9000 §14.1)",
        "info",
        "RFC 9000",
    ),
    "quic.vn-malformed": KindSpec(
        "quic.vn-malformed", "quicprobe", "Reply looked like VN but is structurally broken", "info"
    ),
    "quic.non-quic-reply": KindSpec(
        "quic.non-quic-reply", "quicprobe", "UDP port answered with non-QUIC payload", "info"
    ),
    "quic.no-response": KindSpec(
        "quic.no-response", "quicprobe", "No answer to the VN probe (filtered?)", "info"
    ),
    "quic.unreachable": KindSpec(
        "quic.unreachable", "quicprobe", "ICMP port unreachable — no QUIC endpoint", "info"
    ),
    # -- dnsprobe ---------------------------------------------------------------
    "dns.no-response": KindSpec(
        "dns.no-response", "dnsprobe", "A resolver did not answer the probe", "info"
    ),
    "dns.consistent": KindSpec(
        "dns.consistent", "dnsprobe", "All resolvers returned identical answers", "info"
    ),
    "dns.divergent": KindSpec(
        "dns.divergent",
        "dnsprobe",
        "Resolvers disagree on the same name — suspected spoofing/poisoning",
        "high",
        "RFC 8499 (DNS terminology)",
    ),
    # -- dhcpprobe ---------------------------------------------------------------
    "dhcp.server-found": KindSpec(
        "dhcp.server-found", "dhcpprobe", "A DHCP server answered the discover", "info"
    ),
    "dhcp.multiple-servers": KindSpec(
        "dhcp.multiple-servers", "dhcpprobe", "More than one DHCP server answered", "medium"
    ),
    "dhcp.rogue-suspected": KindSpec(
        "dhcp.rogue-suspected",
        "dhcpprobe",
        "Offer from a server outside --known-server — suspected rogue",
        "high",
    ),
    "dhcp.no-offers": KindSpec(
        "dhcp.no-offers", "dhcpprobe", "No DHCP offer received", "info"
    ),
    # -- fuzz ---------------------------------------------------------------
    "fuzz.target.unreachable": KindSpec(
        "fuzz.target.unreachable", "fuzz", "Target failed liveness checks before fuzzing", "info"
    ),
    "fuzz.host.unresponsive": KindSpec(
        "fuzz.host.unresponsive",
        "fuzz",
        "Target stopped answering after a mutant — likely crash; mutant saved",
        "high",
    ),
    # -- wifi ---------------------------------------------------------------
    "wifi.deauth.storm": KindSpec(
        "wifi.deauth.storm", "wifi", "Deauth frame rate above threshold on a BSSID", "high"
    ),
    "wifi.rogue-ap": KindSpec(
        "wifi.rogue-ap", "wifi", "AP broadcasting an SSID outside the known list", "high"
    ),
    "wifi.evil-twin": KindSpec(
        "wifi.evil-twin", "wifi", "Known SSID advertised from an unknown BSSID", "medium"
    ),
    # -- synthetic ---------------------------------------------------------------
    "trace.replayed": KindSpec(
        "trace.replayed", "synthetic", "Synthetic trace replayed via tcpreplay", "info"
    ),
    # -- runtime / admin findings (cli) -----------------------------------------
    "capture.done": KindSpec("capture.done", "sniff", "Capture finished", "info"),
    "trace.written": KindSpec("trace.written", "sniff", "Capture streamed to a pcap file", "info"),
    "inspect.done": KindSpec("inspect.done", "inspect", "Evidence bytes decoded", "info"),
    "pcap.summary": KindSpec("pcap.summary", "pcap", "Streaming pcap statistics", "info"),
    "run.show": KindSpec("run.show", "report", "One historical run retrieved", "info"),
    "diff.added": KindSpec(
        "diff.added", "report", "Finding present in run B, absent in run A", "info"
    ),
    "diff.removed": KindSpec(
        "diff.removed", "report", "Finding present in run A, absent in run B", "info"
    ),
    "diff.changed": KindSpec(
        "diff.changed", "report", "Finding identity unchanged, detail/state changed", "info"
    ),
    "mitm.planned": KindSpec("mitm.planned", "mitm", "ARP poisoning dry-run plan", "medium"),
    "mitm.session": KindSpec("mitm.session", "mitm", "ARP poisoning session summary", "medium"),
    # -- kinds registry (admin) -------------------------------------------
    "kinds.registry": KindSpec(
        "kinds.registry", "kinds", "The finding-kind registry itself (table)", "info"
    ),
    "kinds.schema": KindSpec(
        "kinds.schema", "kinds", "JSON Schema of the findings payload", "info"
    ),
    # -- verify ---------------------------------------------------------------
    "verify.summary": KindSpec(
        "verify.summary", "verify", "Chain-of-custody totals for one report", "info"
    ),
    "verify.tampered": KindSpec(
        "verify.tampered", "verify", "Evidence hash no longer matches its bytes", "high"
    ),
    "verify.unknown-kind": KindSpec(
        "verify.unknown-kind", "verify", "Finding kind is not registered in the kinds registry", "info"
    ),
    "verify.signature": KindSpec(
        "verify.signature", "sign", "Ed25519 DSSE signature over the report verified", "info",
        "DSSE v1 (secure-systems-lab/dsse)",
    ),
    "report.signed": KindSpec(
        "report.signed", "sign", "Report wrapped in a DSSE envelope (report.json.dsse)", "info"
    ),
    "keys.generated": KindSpec(
        "keys.generated", "sign", "Ed25519 signing keypair generated", "info"
    ),
    "verify.proof": KindSpec(
        "verify.proof", "sign", "Merkle inclusion proof for one finding (selective disclosure)", "info",
        "Certificate Transparency model",
    ),
    # -- replay -----------------------------------------------------------------
    "replay.sent": KindSpec(
        "replay.sent", "replay", "Evidence bytes re-sent verbatim — the proof is executable", "info"
    ),
    # -- blindspots ---------------------------------------------------------------
    "blindspot.unresolved-ports": KindSpec(
        "blindspot.unresolved-ports", "blindspot", "Ports with no reply — open vs closed unknowable under filtering", "info"
    ),
    "blindspot.silent-hosts": KindSpec(
        "blindspot.silent-hosts", "blindspot", "Hosts with no ICMP reply — down or filtered, unknowable from here", "info"
    ),
    "blindspot.cert-unknown": KindSpec(
        "blindspot.cert-unknown", "blindspot", "No ServerHello — certificate health unknown, not good", "info"
    ),
    "blindspot.port-state-unknown": KindSpec(
        "blindspot.port-state-unknown", "blindspot", "Conversation could not open — port state stays unknown", "info"
    ),
    # -- assert -----------------------------------------------------------------
    "assert.pass": KindSpec(
        "assert.pass", "assert", "Desired-state promise kept", "info"
    ),
    "assert.violated": KindSpec(
        "assert.violated", "assert", "Desired-state promise broken — the network drifted", "high"
    ),
    # -- ledger -----------------------------------------------------------------
    "ledger.unsolicited": KindSpec(
        "ledger.unsolicited", "ledger", "Remote talker with no matching probe — the network spoke first", "info"
    ),
}

# diff.added for an open port is escalated by the report module (LOW)
KIND_SEVERITY_OVERRIDES: dict[tuple[str, str], str] = {
    ("diff.added", "port.open"): "low",
}


def register_kind(spec: KindSpec) -> None:
    """Let plugins add kinds; builtins always win (re-registration is a no-op)."""
    KINDS.setdefault(spec.kind, spec)


def get_kind(kind: str) -> KindSpec | None:
    return KINDS.get(kind)


def kinds_schema() -> dict:
    """JSON Schema (draft-07) for the findings payload, kinds as a closed enum.

    draft-07 is a deliberate compatibility choice (SARIF 2.1.0 and Semgrep
    both declare draft-07); the payload additionally carries
    ``schema_version`` so OSV-style additive evolution stays auditable.
    """
    kind_enum = {
        "oneOf": [
            {"const": k, "description": f"{s.meaning} (default severity: {s.severity})"}
            for k, s in sorted(KINDS.items())
        ]
    }
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "vtknet findings",
        "type": "object",
        "required": ["schema_version", "command", "findings"],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION, "description": "SemVer; additive-only evolution"},
            "command": {"type": "string"},
            "args": {"type": "object"},
            "started": {"type": "string"},
            "finished": {"type": "string"},
            "duration_s": {"type": "number"},
            "stats": {"type": "object"},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["module", "kind", "host", "severity"],
                    "properties": {
                        "id": {"type": "string"},
                        "timestamp": {"type": "string"},
                        "module": {"type": "string"},
                        "kind": kind_enum,
                        "host": {"type": "string"},
                        "port": {"type": ["integer", "null"]},
                        "state": {"type": ["string", "null"]},
                        "severity": {"enum": ["info", "low", "medium", "high"]},
                        "detail": {"type": "object"},
                        "evidence": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["kind", "data"],
                                "properties": {
                                    "kind": {"type": "string"},
                                    "data": {"type": "string"},
                                    "note": {"type": "string"},
                                    "sha256": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def render_kinds_text() -> str:
    """Aligned human-readable table of all registered kinds."""
    lines = [f"{'kind':<28} {'module':<10} {'sev':<7} meaning"]
    for k in sorted(KINDS):
        s = KINDS[k]
        lines.append(f"{s.kind:<28} {s.module:<10} {s.severity:<7} {s.meaning}")
    return "\n".join(lines)


# -- sprint 2/3/5 kinds (registered here so the registry stays the single source) --

for _kind, _meaning, _sev in (
    ("eval.detected", "IDS alert matched the scenario's ground-truth signal", "info"),
    ("eval.missed", "IDS produced no alert matching the expected signal — detection gap", "high"),
    ("watch.added", "Watch round: a finding appeared that was absent last round", "low"),
    ("watch.removed", "Watch round: a finding from last round is gone", "low"),
    ("watch.changed", "Watch round: a known finding changed state/detail", "medium"),
    ("notarize.manifest", "Notarization manifest: Merkle root over the report's evidence", "info"),
    ("notarize.rekor-entry", "Hash recorded in the Rekor transparency log (public timestamp)", "info"),
    ("fuzz.minimized", "Crashing mutant minimized to its field-minimal form", "info"),
    ("verify.deep.holds", "Deep verify: the evidence bytes still support the claim", "info"),
    ("verify.deep.contradicts", "Deep verify: the evidence bytes contradict the claim", "medium"),
    ("verify.deep.skipped", "Deep verify: evidence not deep-checkable (recorded, not failed)", "info"),
):
    register_kind(KindSpec(_kind, _kind.split(".")[0], _meaning, _sev))
