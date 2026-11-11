"""Tests for the out-of-the-box round: Merkle proofs, replay, blindspots,
assert, ledger."""

from __future__ import annotations

import json

import pytest
from scapy.all import IP, TCP, Ether

from vtknet.cli import main
from vtknet.core.assertions import evaluate_assertions, load_rules
from vtknet.core.blindspot import blindspots_for
from vtknet.core.engine import Engine, EngineConfig
from vtknet.core.ledger import ledger_unsolicited
from vtknet.core.models import Finding, ScanResult, sha256_hex
from vtknet.core.replay import find_finding_evidence, load_report, replay_finding
from vtknet.core.signing import (
    evidence_leaves,
    keygen,
    merkle_proof,
    merkle_root,
    merkle_verify,
    sign_report,
)


def sample_report(n: int = 3) -> dict:
    findings = []
    for i in range(n):
        data = f"evidence-{i}"
        findings.append(
            {
                "id": f"id{i}",
                "module": "scanner",
                "kind": "port.open",
                "host": f"10.0.0.{i + 1}",
                "port": 443,
                "severity": "info",
                "detail": {},
                "evidence": [{"kind": "packet_hex", "data": data,
                              "note": "", "sha256": sha256_hex(data)}],
            }
        )
    return {"command": "scan", "started": "t", "findings": findings}


# -- 11.1 Merkle ------------------------------------------------------------


def test_merkle_single_leaf_root_is_leaf():
    assert merkle_root([sha256_hex("a")]) == sha256_hex("a")


def test_merkle_two_leaves_root_is_parent_hash():
    a, b = sha256_hex("a"), sha256_hex("b")
    import hashlib

    assert merkle_root([a, b]) == hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()


def test_merkle_odd_count_duplicates_last():
    # 3 leaves: root == H(H(a,b) + H(c,c)) by the duplicate-last convention
    import hashlib

    a, b, c = (sha256_hex(x) for x in "abc")
    left = hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).digest()
    right = hashlib.sha256(bytes.fromhex(c) + bytes.fromhex(c)).digest()
    assert merkle_root([a, b, c]) == hashlib.sha256(left + right).hexdigest()


def test_merkle_proof_roundtrip_all_positions():
    leaves = [sha256_hex(f"leaf{i}") for i in range(5)]
    root = merkle_root(leaves)
    for i in range(5):
        assert merkle_verify(leaves[i], merkle_proof(leaves, i), root, i)


def test_merkle_proof_fails_on_foreign_leaf():
    leaves = [sha256_hex(f"leaf{i}") for i in range(4)]
    root = merkle_root(leaves)
    assert not merkle_verify(sha256_hex("evil"), merkle_proof(leaves, 0), root, 0)


def test_envelope_carries_merkle_root_and_proofs_work(tmp_path):
    priv, _, _ = keygen(tmp_path / "k")
    report = sample_report()
    envelope = sign_report(report, priv)
    root = envelope["vtknetMerkleRoot"]
    assert root == merkle_root(evidence_leaves(report))
    # selective disclosure of finding id1 — signed root, single leaf
    leaves = evidence_leaves(report)
    proof = merkle_proof(leaves, 1)
    assert merkle_verify(leaves[1], proof, root, 1)


def test_cli_prove_emits_verifiable_proof(tmp_path, capsys):
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(sample_report()), encoding="utf-8")
    assert main(["verify", str(rp), "--prove", "id2", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    proof = out["findings"][0]["detail"]
    assert proof["verified"] is True
    assert proof["finding_id"] == "id2"
    # an independent consumer re-checks the proof against the report's root
    report = sample_report()
    leaves = evidence_leaves(report)
    assert merkle_verify(proof["leaf"], proof["proof"], merkle_root(leaves), proof["index"])


# -- 11.8 replay ------------------------------------------------------------


def test_replay_sends_evidence_bytes_in_dry_run(capsys):
    from scapy.all import IP, TCP

    pkt = IP(dst="203.0.113.9") / TCP(dport=443, flags="S")
    findings, stats = replay_finding(Engine(EngineConfig(dry_run=True)), bytes(pkt).hex(), count=2)
    assert stats == {"sent": 2}
    assert findings[0].kind == "replay.sent"
    assert findings[0].host == "203.0.113.9"


def test_replay_missing_finding_raises():
    report = {"command": "scan", "findings": [{"id": "a", "evidence": []}]}
    with pytest.raises(ValueError, match="not in report"):
        find_finding_evidence(report, "nope")
    with pytest.raises(ValueError, match="no packet_hex"):
        find_finding_evidence(report, "a")


def test_replay_loads_dsse_envelopes(tmp_path):
    priv, pub, _ = keygen(tmp_path / "k")
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(sample_report(1)), encoding="utf-8")
    main(["sign", str(rp), "--key", str(priv)])
    env = load_report(str(tmp_path / "r.json.dsse"), pub=str(pub))
    assert env["findings"][0]["id"] == "id0"


# -- 11.7 blindspots ----------------------------------------------------------


def test_blindspot_for_filtered_scan_ports():
    r = ScanResult(command="scan", args={"target": "10.0.0.5"})
    r.stats = {"filtered": 900}
    spots = blindspots_for(r)
    assert spots[0].kind == "blindspot.unresolved-ports"
    assert spots[0].detail["ports"] == 900


def test_blindspot_for_silent_sweep_hosts():
    r = ScanResult(command="sweep", args={"target": "10.0.0.0/24"})
    r.stats = {"sent": 254, "answered": 12}
    spots = blindspots_for(r)
    assert spots[0].kind == "blindspot.silent-hosts"
    assert spots[0].detail["hosts"] == 242


def test_blindspot_for_unknown_tls_cert():
    r = ScanResult(command="tls", args={"target": "10.0.0.5"})
    r.findings = [Finding(module="tlsprobe", kind="tls.no-response", host="10.0.0.5")]
    spots = blindspots_for(r)
    assert spots[0].kind == "blindspot.cert-unknown"


def test_no_blindspot_when_everything_resolved():
    r = ScanResult(command="scan", args={"target": "10.0.0.5"})
    r.stats = {"filtered": 0}
    assert blindspots_for(r) == []


# -- 11.5 assert ---------------------------------------------------------------


def test_assert_present_and_absent():
    rules = {"assertions": [
        {"expect": "present", "kind": "port.open", "host": "10.0.0.5", "port": 443},
        {"expect": "absent", "kind": "dhcp.rogue-suspected"},
    ]}
    report = {"findings": [
        {"kind": "port.open", "host": "10.0.0.5", "port": 443},
        {"kind": "port.open", "host": "10.0.0.6", "port": 80},
    ]}
    findings, stats = evaluate_assertions(rules, report)
    assert stats == {"assertions": 2, "passed": 2, "violated": 0}
    assert all(f.kind == "assert.pass" for f in findings)


def test_assert_violations_are_high_and_counted():
    rules = {"assertions": [
        {"expect": "present", "kind": "port.open", "host": "10.0.0.5", "port": 443},
        {"expect": "absent", "kind": "ledger.unsolicited", "host": "9.9.9.9"},
    ]}
    report = {"findings": [
        {"kind": "ledger.unsolicited", "host": "9.9.9.9"},
    ]}
    findings, stats = evaluate_assertions(rules, report)
    assert stats["violated"] == 2 and stats["passed"] == 0
    assert all(f.severity.value == "high" and f.kind == "assert.violated" for f in findings)


def test_assert_rules_shape_errors(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"assertions": [{"expect": "maybe", "kind": "x"}]}))
    with pytest.raises(ValueError, match="expect"):
        load_rules(str(bad))


def test_cli_assert_exit_codes(tmp_path, capsys):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"assertions": [
        {"expect": "present", "kind": "port.open", "host": "10.0.0.5", "port": 443},
    ]}), encoding="utf-8")
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"findings": [
        {"kind": "port.open", "host": "10.0.0.5", "port": 443}]}), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"findings": []}), encoding="utf-8")
    assert main(["assert", str(rules), "--against", str(ok), "--json"]) == 0
    assert main(["assert", str(rules), "--against", str(bad), "--json"]) == 1  # CI-gate contract


# -- 11.6 ledger ----------------------------------------------------------------


def _pkt(src, dst, dport=443):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=55555, dport=dport, flags="S")


def test_ledger_flags_unaccounted_talkers():
    ours = {"10.0.0.5"}
    pkts = [
        _pkt("9.9.9.9", "10.0.0.5"),           # inbound — unaccounted
        _pkt("9.9.9.9", "10.0.0.5"),           # same talker, grouped
        _pkt("10.0.0.5", "9.9.9.9"),           # our own outbound — not a credit
        _pkt("8.8.8.8", "10.0.0.99"),          # not addressed to us — ignored
    ]
    findings, stats = ledger_unsolicited(pkts, our_ips=ours)
    assert stats == {"inbound": 2, "talkers": 1}
    assert findings[0].host == "9.9.9.9"
    assert findings[0].detail["packets"] == 2
    assert findings[0].evidence  # first packet kept as proof


def test_ledger_talker_cap_never_explodes():
    ours = {"10.0.0.5"}
    pkts = [_pkt(f"10.9.{i // 250}.{i % 250}", "10.0.0.5") for i in range(300)]
    findings, _ = ledger_unsolicited(pkts, our_ips=ours)
    assert len(findings) <= 256  # hostile flood stays bounded
