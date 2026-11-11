"""Tests for DSSE-signed reports (core/signing.py) and SARIF fingerprints."""

from __future__ import annotations

import base64
import json
import stat

import pytest

from vtknet.cli import main
from vtknet.core.models import Finding, ScanResult, sha256_hex
from vtknet.core.report import finding_fingerprint, render_sarif
from vtknet.core.signing import (
    VTKNET_PAYLOAD_TYPE,
    canonical_json,
    keygen,
    pae,
    sign_report,
    verify_envelope,
)


def sample_report() -> dict:
    ev = {"kind": "packet_hex", "data": "deadbeef", "note": "x", "sha256": sha256_hex("deadbeef")}
    return {
        "command": "banner",
        "started": "2026-01-01T00:00:00Z",
        "findings": [
            {
                "id": "abc123",
                "module": "banner",
                "kind": "banner.grabbed",
                "host": "10.0.0.5",
                "port": 22,
                "severity": "info",
                "detail": {"banner": "SSH-2.0-OpenSSH_9"},
                "evidence": [ev],
            }
        ],
    }


# -- DSSE primitives --------------------------------------------------------


def test_pae_known_answer():
    # PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    assert pae("T", b"AB") == b"DSSEv1 1 T 2 AB"


def test_canonical_json_is_stable_and_sorted():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


# -- keys -------------------------------------------------------------------


def test_keygen_writes_keypair_with_private_mode_0600(tmp_path):
    priv, pub, keyid = keygen(tmp_path)
    assert priv.exists() and pub.exists()
    assert len(keyid) == 16
    mode = stat.S_IMODE(priv.stat().st_mode)
    assert mode == 0o600
    pub.read_text().startswith("-----BEGIN PUBLIC KEY-----")


# -- sign / verify roundtrip -------------------------------------------------


def test_sign_and_verify_roundtrip(tmp_path):
    priv, pub, _ = keygen(tmp_path)
    report = sample_report()
    envelope = sign_report(report, priv)
    assert envelope["payloadType"] == VTKNET_PAYLOAD_TYPE
    body = verify_envelope(envelope, pub)
    assert body == canonical_json(report)
    assert json.loads(body)["findings"][0]["host"] == "10.0.0.5"


def test_verify_rejects_tampered_payload(tmp_path):
    priv, pub, _ = keygen(tmp_path)
    envelope = sign_report(sample_report(), priv)
    body = json.loads(base64.b64decode(envelope["payload"]))
    body["findings"][0]["host"] = "9.9.9.9"  # one byte of semantics, total breakage
    envelope["payload"] = base64.b64encode(json.dumps(body).encode()).decode()
    with pytest.raises(ValueError, match="verification failed"):
        verify_envelope(envelope, pub)


def test_verify_rejects_wrong_key(tmp_path):
    priv, _, _ = keygen(tmp_path / "a")
    _, other_pub, _ = keygen(tmp_path / "b")
    envelope = sign_report(sample_report(), priv)
    with pytest.raises(ValueError):
        verify_envelope(envelope, other_pub)


def test_verify_rejects_foreign_payload_type(tmp_path):
    priv, pub, _ = keygen(tmp_path)
    envelope = sign_report(sample_report(), priv)
    envelope["payloadType"] = "application/json"  # DSSE forbids generic types
    with pytest.raises(ValueError, match="payloadType"):
        verify_envelope(envelope, pub)


def test_verify_fails_closed_on_garbage(tmp_path):
    _, pub, _ = keygen(tmp_path)
    with pytest.raises(ValueError):
        verify_envelope({"hello": 1}, pub)
    with pytest.raises(ValueError, match="base64"):
        verify_envelope({"payload": "!!!not-base64!!!", "payloadType": VTKNET_PAYLOAD_TYPE,
                         "signatures": [{"keyid": "x", "sig": "AAAA"}]}, pub)


# -- CLI end-to-end: keygen -> sign -> verify --------------------------------


def test_cli_sign_and_verify_flow(tmp_path):
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(sample_report()), encoding="utf-8")
    keys = tmp_path / "keys"
    assert main(["keygen", "--out-dir", str(keys), "--json"]) == 0
    priv = next(keys.glob("*.key"))
    pub = next(keys.glob("*.pub"))
    assert main(["sign", str(rp), "--key", str(priv), "--json"]) == 0
    env = tmp_path / "r.json.dsse"
    assert env.exists()
    assert main(["verify", str(env), "--key", str(pub), "--json"]) == 0


def test_cli_verify_fails_closed_on_tampered_envelope(tmp_path):
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(sample_report()), encoding="utf-8")
    keys = tmp_path / "keys"
    main(["keygen", "--out-dir", str(keys)])
    priv, pub = next(keys.glob("*.key")), next(keys.glob("*.pub"))
    main(["sign", str(rp), "--key", str(priv)])
    env = tmp_path / "r.json.dsse"
    envelope = json.loads(env.read_text(encoding="utf-8"))
    body = json.loads(base64.b64decode(envelope["payload"]))
    body["findings"][0]["detail"]["banner"] = "EVIL-SSH"
    envelope["payload"] = base64.b64encode(json.dumps(body).encode()).decode()
    bad = tmp_path / "bad.dsse"
    bad.write_text(json.dumps(envelope), encoding="utf-8")
    assert main(["verify", str(bad), "--key", str(pub)]) == 2  # fail closed


# -- SARIF stable fingerprints -----------------------------------------------


def _finding(detail: dict) -> Finding:
    return Finding(module="scanner", kind="port.open", host="10.0.0.5", port=443,
                   state="open", detail=detail)


def test_fingerprint_is_stable_across_runs():
    assert finding_fingerprint(_finding({"scan": "syn"})) == finding_fingerprint(
        _finding({"scan": "syn"})
    )


def test_fingerprint_ignores_volatile_detail():
    base = finding_fingerprint(_finding({"scan": "syn", "ttl": 64}))
    drifted = finding_fingerprint(_finding({"scan": "syn", "ttl": 128}))
    assert base == drifted  # TTL varies per hop/run — not part of identity


def test_fingerprint_changes_on_real_change():
    assert finding_fingerprint(_finding({"scan": "syn"})) != finding_fingerprint(
        _finding({"scan": "ack"})
    )


def test_sarif_carries_github_grade_fingerprints():
    r = ScanResult(command="scan")
    r.findings = [_finding({"scan": "syn"})]
    doc = json.loads(render_sarif(r))
    res = doc["runs"][0]["results"][0]
    fp = res["partialFingerprints"]["primaryLocationLineHash"]  # the key GitHub reads
    assert res["partialFingerprints"]["vtknetFindingHash/v1"] == fp
    assert res["correlationGuid"]  # deterministic identity
    assert doc["runs"][0]["results"][0]["correlationGuid"] == res["correlationGuid"]


def test_sarif_rules_come_from_kinds_registry():
    r = ScanResult(command="scan")
    r.findings = [_finding({"scan": "syn"})]
    doc = json.loads(render_sarif(r))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "accepted" in rule["shortDescription"]["text"]  # registry meaning, not a stub
    assert rule["fullDescription"]["text"]  # required by GitHub's importer
    assert rule["properties"]["security-severity"] == "0.0"  # info default for port.open
