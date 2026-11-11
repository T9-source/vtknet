"""Sprint 1 additions: evidence SHA-256 chain anchor + kinds registry."""

from __future__ import annotations

import json

import pytest

from vtknet.core.kinds import (
    KINDS,
    KindSpec,
    get_kind,
    kinds_schema,
    register_kind,
    render_kinds_text,
)
from vtknet.core.models import Evidence, Finding, ScanResult
from vtknet.core.report import render_sarif

# -- evidence sha256 -------------------------------------------------------


def test_evidence_sha256_stamped_automatically():
    ev = Evidence("packet_hex", "aabbccdd", "demo")
    assert ev.sha256
    assert len(ev.sha256) == 64


def test_evidence_sha256_is_sha256_of_data_utf8():
    import hashlib

    ev = Evidence("packet_hex", "aabbccdd")
    assert ev.sha256 == hashlib.sha256(b"aabbccdd").hexdigest()


def test_evidence_sha256_changes_with_data():
    a, b = Evidence("packet_hex", "aa"), Evidence("packet_hex", "bb")
    assert a.sha256 != b.sha256


def test_evidence_sha256_explicit_value_is_respected():
    ev = Evidence("packet_hex", "aa", sha256="manual-hash")
    assert ev.sha256 == "manual-hash"


def test_evidence_to_dict_includes_sha256():
    d = Evidence("pcap", "/tmp/x.pcap").to_dict()
    assert d["sha256"]


def test_finding_json_roundtrip_keeps_sha256():
    f = Finding(module="t", kind="k", host="h", evidence=[Evidence("packet_hex", "ffee")])
    loaded = json.loads(json.dumps(f.to_dict()))
    assert loaded["evidence"][0]["sha256"] == f.evidence[0].sha256


# -- kinds registry ---------------------------------------------------------


def test_kinds_registry_has_core_builtin_kinds():
    for k in ("host.alive", "port.open", "dns.divergent", "dhcp.rogue-suspected", "banner.grabbed"):
        assert k in KINDS, f"missing core kind: {k}"


def test_get_kind_unknown_returns_none():
    assert get_kind("no.such.kind") is None


def test_severities_are_valid():
    valid = {"info", "low", "medium", "high"}
    for k, s in KINDS.items():
        assert s.severity in valid, f"{k}: bad severity {s.severity!r}"


def test_register_kind_never_shadows_builtin():
    spec = KindSpec("port.open", "evil", "shadow", "high")
    register_kind(spec)
    assert KINDS["port.open"].module == "scanner"


def test_register_kind_adds_new():
    spec = KindSpec("myplugin.thing", "myplugin", "does a thing", "low")
    register_kind(spec)
    try:
        assert KINDS["myplugin.thing"] is spec
    finally:
        KINDS.pop("myplugin.thing", None)


def test_render_kinds_text_is_aligned_table():
    text = render_kinds_text()
    assert "kind" in text and "host.alive" in text


def test_kinds_schema_is_valid_draft07_shape():
    schema = kinds_schema()
    assert schema["$schema"].endswith("draft-07/schema#")
    props = schema["properties"]["findings"]["items"]["properties"]
    assert "kind" in props and "severity" in props


def test_scan_result_json_validates_against_schema_shape():
    schema = kinds_schema()
    doc = json.loads(
        ScanResult(command="scan").to_json()
    )  # minimal run; required fields present
    for req in schema["required"]:
        assert req in doc


# -- SARIF exporter ----------------------------------------------------------


def _sample_result() -> ScanResult:
    f = Finding(
        module="scanner",
        kind="port.open",
        host="10.0.0.5",
        port=443,
        state="open",
        evidence=[Evidence("packet_hex", "ffee", "syn reply")],
    )
    r = ScanResult(command="scan")
    r.findings = [f]
    return r


def test_sarif_is_valid_210_document():
    doc = json.loads(render_sarif(_sample_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "vtknet"
    assert any(rule["id"] == "port.open" for rule in run["tool"]["driver"]["rules"])


def test_sarif_result_fields_map_findings():
    doc = json.loads(render_sarif(_sample_result()))
    res = doc["runs"][0]["results"][0]
    assert res["ruleId"] == "port.open"
    assert res["level"] == "note"  # info -> note
    assert "10.0.0.5:443" in res["message"]["text"]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "tcp://10.0.0.5:443"
    assert res["properties"]["evidenceSha256"]


def test_sarif_severity_mapping():
    cases = {"info": "note", "low": "note", "medium": "warning", "high": "error"}
    for sev, level in cases.items():
        f = Finding(module="m", kind="k", host="h")
        f.severity = f.severity.__class__(sev)
        r = ScanResult(command="c")
        r.findings = [f]
        doc = json.loads(render_sarif(r))
        assert doc["runs"][0]["results"][0]["level"] == level


def test_sarif_empty_findings_ok():
    doc = json.loads(render_sarif(ScanResult(command="scan")))
    assert doc["runs"][0]["results"] == []


def test_sarif_high_severity_is_error():
    f = Finding(module="m", kind="dns.divergent", host="h")
    f.severity = f.severity.__class__("high")
    r = ScanResult(command="dns")
    r.findings = [f]
    doc = json.loads(render_sarif(r))
    assert doc["runs"][0]["results"][0]["level"] == "error"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__]))
