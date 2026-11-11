"""Tests for the evidence verifier (vtk verify)."""

from __future__ import annotations

import json

import pytest

from vtknet.cli import main
from vtknet.core.models import sha256_hex
from vtknet.core.verify import verify_report, verify_report_file


def make_report(
    ev_data: str = "deadbeef",
    ev_sha: str | None = None,
    include_sha: bool = True,
    kind: str = "banner.grabbed",
) -> dict:
    ev: dict = {"kind": "packet_hex", "data": ev_data, "note": "x"}
    if include_sha:
        ev["sha256"] = ev_sha if ev_sha is not None else sha256_hex(ev_data)
    return {
        "command": "banner",
        "started": "2026-01-01T00:00:00Z",
        "findings": [
            {
                "id": "abc123",
                "module": "banner",
                "kind": kind,
                "host": "10.0.0.5",
                "port": 22,
                "severity": "info",
                "detail": {},
                "evidence": [ev],
            }
        ],
    }


# -- happy path -----------------------------------------------------------


def test_ok_report_has_no_tamper_findings():
    findings, stats = verify_report(make_report())
    kinds = [f.kind for f in findings]
    assert "verify.tampered" not in kinds
    assert stats["hashed_ok"] == 1
    assert stats["tampered"] == 0
    summary = findings[0]
    assert summary.kind == "verify.summary"
    assert summary.detail["hashed_ok"] == 1


def test_summary_leads_the_findings():
    findings, _ = verify_report(make_report())
    assert findings[0].kind == "verify.summary"
    assert findings[0].severity.value == "info"


# -- tamper detection ------------------------------------------------------


def test_modified_bytes_are_tampered():
    findings, stats = verify_report(make_report(ev_sha=sha256_hex("c0ffee")))
    tampered = [f for f in findings if f.kind == "verify.tampered"]
    assert len(tampered) == 1
    assert tampered[0].severity.value == "high"
    assert tampered[0].detail["stored_sha256"] == sha256_hex("c0ffee")
    assert tampered[0].detail["actual_sha256"] == sha256_hex("deadbeef")
    assert stats["tampered"] == 1
    assert findings[0].severity.value == "medium"  # summary escalates


def test_missing_evidence_data_counts_as_tampered():
    report = make_report()
    report["findings"][0]["evidence"][0]["data"] = ""
    findings, stats = verify_report(report)
    assert stats["tampered"] == 1
    assert any(f.kind == "verify.tampered" for f in findings)


# -- registry / legacy handling --------------------------------------------


def test_unknown_kind_is_flagged_not_failed():
    findings, stats = verify_report(make_report(kind="totally.unregistered"))
    flagged = [f for f in findings if f.kind == "verify.unknown-kind"]
    assert len(flagged) == 1
    assert stats["unknown_kind"] == 1


def test_legacy_report_without_hashes_is_not_tampered():
    findings, stats = verify_report(make_report(include_sha=False))
    assert not any(f.kind == "verify.tampered" for f in findings)
    assert stats["no_hash"] == 1


# -- file loading -----------------------------------------------------------


def test_verify_report_file_roundtrip(tmp_path):
    p = tmp_path / "report.json"
    p.write_text(json.dumps(make_report()), encoding="utf-8")
    findings, stats = verify_report_file(str(p))
    assert stats["hashed_ok"] == 1
    assert findings[0].kind == "verify.summary"


def test_verify_report_file_rejects_non_json(tmp_path):
    p = tmp_path / "junk.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not a valid"):
        verify_report_file(str(p))


def test_verify_report_file_rejects_wrong_shape(tmp_path):
    p = tmp_path / "other.json"
    p.write_text(json.dumps({"hello": 1}), encoding="utf-8")
    with pytest.raises(ValueError, match="not a vtknet report"):
        verify_report_file(str(p))


# -- CLI wiring --------------------------------------------------------------


def test_cli_verify_exit_ok_on_tampered_report(tmp_path):
    # verify ran fine; the tamper verdict lives in findings, not exit codes
    p = tmp_path / "report.json"
    p.write_text(json.dumps(make_report(ev_sha=sha256_hex("c0ffee"))), encoding="utf-8")
    assert main(["verify", str(p), "--json"]) == 0


def test_cli_verify_usage_error_on_missing_file():
    assert main(["verify", "/nonexistent/report.json"]) == 2  # usage error, clean exit
