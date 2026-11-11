"""Evidence verifier: re-derive every claim's proof from its own bytes.

``vtk verify report.json`` walks the findings of a saved ScanResult and
re-checks the chain of custody:

- the stored ``sha256`` must equal the hash of the evidence data as it
  stands now — a mismatch means the bytes changed after the stamp
  (``verify.tampered``, high);
- every finding ``kind`` must be registered in the kinds registry —
  unregistered labels mean a module or plugin drifted from the contract
  (``verify.unknown-kind``, info);
- a summary finding carries the totals (``verify.summary``).

Offline, no root, never auto-saved. Reports from before 0.8.0 carry no
hashes — their evidences are counted as ``no_hash`` instead of failing.
"""

from __future__ import annotations

import logging
from typing import Any

from vtknet.core.kinds import get_kind
from vtknet.core.models import Finding, Severity, sha256_hex

log = logging.getLogger("vtknet.verify")

REQUIRED_FINDING_FIELDS = ("module", "kind", "host", "severity")


def verify_report(report: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    """Verify one parsed report dict; returns (findings, stats).

    Malformed evidence entries (missing data) count as tampered — an
    evidence that cannot even be read is not an evidence.
    """
    tampered = 0
    unknown_kind = 0
    no_hash = 0
    hashed_ok = 0
    evidences = 0

    findings_out: list[Finding] = []
    report_findings = report.get("findings", [])

    for f in report_findings:
        host = str(f.get("host", "-"))
        fid = str(f.get("id", "?"))
        fkind = str(f.get("kind", "?"))

        if get_kind(fkind) is None:
            unknown_kind += 1
            findings_out.append(
                Finding(
                    module="verify",
                    kind="verify.unknown-kind",
                    host=host,
                    severity=Severity.INFO,
                    detail={"finding_id": fid, "kind": fkind,
                            "note": "not registered in the kinds registry"},
                )
            )

        for ev in f.get("evidence", []):
            evidences += 1
            data = ev.get("data")
            stored = ev.get("sha256", "")
            if not isinstance(data, str) or not data:
                tampered += 1
                findings_out.append(
                    Finding(
                        module="verify",
                        kind="verify.tampered",
                        host=host,
                        severity=Severity.HIGH,
                        detail={"finding_id": fid, "kind": fkind,
                                "note": "evidence data missing or unreadable"},
                    )
                )
                continue
            if not stored:
                no_hash += 1  # pre-0.8.0 report: nothing to check, not a failure
                continue
            actual = sha256_hex(data)
            if actual != stored:
                tampered += 1
                findings_out.append(
                    Finding(
                        module="verify",
                        kind="verify.tampered",
                        host=host,
                        severity=Severity.HIGH,
                        detail={
                            "finding_id": fid,
                            "kind": fkind,
                            "evidence_note": ev.get("note", ""),
                            "stored_sha256": stored,
                            "actual_sha256": actual,
                            "note": "evidence bytes changed after the stamp",
                        },
                    )
                )
            else:
                hashed_ok += 1

    summary = Finding(
        module="verify",
        kind="verify.summary",
        host=str(report.get("command", "-")),
        detail={
            "report_command": report.get("command", ""),
            "report_started": report.get("started", ""),
            "findings_in_report": len(report_findings),
            "evidences": evidences,
            "hashed_ok": hashed_ok,
            "tampered": tampered,
            "no_hash": no_hash,
            "unknown_kind": unknown_kind,
        },
    )
    if tampered or unknown_kind:
        summary.severity = Severity.LOW if not tampered else Severity.MEDIUM
    findings_out.insert(0, summary)
    stats = {
        "findings": len(report_findings),
        "evidences": evidences,
        "hashed_ok": hashed_ok,
        "tampered": tampered,
        "no_hash": no_hash,
        "unknown_kind": unknown_kind,
    }
    log.info(
        "verify: %d evidence(s) — %d hash-ok, %d tampered, %d unhashed, %d unknown kinds",
        evidences,
        hashed_ok,
        tampered,
        no_hash,
        unknown_kind,
    )
    return findings_out, stats


def verify_report_file(path: str) -> tuple[list[Finding], dict[str, int]]:
    """Load a saved JSON report and verify it. Raises ValueError on bad JSON."""
    import json

    try:
        with open(path, encoding="utf-8") as fh:
            report = json.load(fh)
    except FileNotFoundError as exc:
        raise ValueError(f"report file not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"cannot read report ({path}): {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"not a valid vtknet JSON report ({path}): {exc}") from exc
    if not isinstance(report, dict) or "findings" not in report:
        raise ValueError(f"not a vtknet report (missing 'findings'): {path}")
    return verify_report(report)
