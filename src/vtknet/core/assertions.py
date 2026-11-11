"""Desired-state assertions — the network as a set of kept promises.

Rules are plain JSON (vtknet needs no YAML dependency):

    {
      "title": "lab baseline",
      "assertions": [
        {"expect": "present", "kind": "port.open",  "host": "10.0.0.5", "port": 443},
        {"expect": "absent",  "kind": "dhcp.rogue-suspected"},
        {"expect": "present", "kind": "tls.cert.expired", "negate": false}
      ]
    }

``expect: present`` demands at least one matching finding; ``absent``
demands none. Matching is by kind + optional host/port. Violations are
``assert.violated`` (high); the CLI exits 1 when anything is violated —
the CI-gate contract. Compose with the Unix pipeline for live mode:
``vtk scan ... --report r.json && vtk assert rules.json --against r.json``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from vtknet.core.models import Finding, Severity

log = logging.getLogger("vtknet.assert")


def load_rules(path: str) -> dict[str, Any]:
    """Load and shape-check an assertion file. Raises ValueError on junk."""
    try:
        rules = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read rules ({path}): {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"not valid JSON ({path}): {exc}") from exc
    if not isinstance(rules, dict) or not isinstance(rules.get("assertions"), list):
        # ValueError on purpose: the CLI maps it to a clean usage error
        raise ValueError(f"rules need an 'assertions' list: {path}")  # noqa: TRY004
    for i, a in enumerate(rules["assertions"]):
        if not isinstance(a, dict) or a.get("expect") not in ("present", "absent"):
            raise ValueError(f"assertion #{i}: expect must be 'present' or 'absent'")
        if not isinstance(a.get("kind"), str) or not a["kind"]:
            raise ValueError(f"assertion #{i}: 'kind' is required")
    return rules


def _matches(assertion: dict[str, Any], finding: dict[str, Any]) -> bool:
    return (
        finding.get("kind") == assertion["kind"]
        and (assertion.get("host") is None or finding.get("host") == assertion["host"])
        and (assertion.get("port") is None or finding.get("port") == assertion["port"])
    )


def evaluate_assertions(
    rules: dict[str, Any], report: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    """Evaluate every assertion against a report's findings.

    Returns (findings, stats); ``violated`` > 0 means the promise is broken.
    """
    out: list[Finding] = []
    passed = violated = 0
    findings = report.get("findings", [])
    for a in rules.get("assertions", []):
        hit = any(_matches(a, f) for f in findings if isinstance(f, dict))
        satisfied = hit if a["expect"] == "present" else not hit
        label = a["expect"]
        detail = {
            "expect": label,
            "kind": a["kind"],
            "host": a.get("host"),
            "port": a.get("port"),
            "matched": hit,
            "title": rules.get("title", ""),
        }
        if satisfied:
            passed += 1
            out.append(
                Finding(module="assert", kind="assert.pass", host=a.get("host") or "-",
                        severity=Severity.INFO, detail=detail)
            )
        else:
            violated += 1
            out.append(
                Finding(module="assert", kind="assert.violated", host=a.get("host") or "-",
                        severity=Severity.HIGH, detail=detail)
            )
    stats = {"assertions": passed + violated, "passed": passed, "violated": violated}
    log.info("assert: %d/%d promises kept", passed, passed + violated)
    return out, stats
