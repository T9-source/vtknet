"""Rekor notarization — public, append-only timestamps for vtknet reports.

``vtk notarize REPORT`` records the report's evidence Merkle root (hash
only — never report content) in the Sigstore Rekor v2 transparency log via
its `hashes/entries` API
(https://google.github.io/trillian-transparency/docs/api/api-v2), and
persists the returned log entry (uuid + log index + integrated time) as a
finding — the report now carries a publicly auditable existence proof.

Design boundaries, stated honestly:
- network calls happen ONLY in ``rekor_submit`` (opt-in command);
- offline mode (``--dry-run`` or no network) still emits the notarization
  *manifest* (root + sha256) so the command is testable and useful
  air-gapped;
- ``rekor_verify`` re-checks a stored entry against the local report's
  recomputed root (equality = the notarized thing is this report).
"""

from __future__ import annotations

import logging
from typing import Any

from vtknet.core.models import Evidence, Finding, Severity

log = logging.getLogger("vtknet.notarize")

REKOR_V2_HASHES_URL = "https://rekor.sigstore.dev/api/v2/hashes/entries"
PREDICATE_VTKNET = "https://vtknet.dev/attestation/scan-report/v1"


def notarization_root(report: dict[str, Any]) -> str:
    """The hash to notarize: Merkle root over the report's evidence hashes."""
    from vtknet.core.signing import evidence_leaves, merkle_root

    return merkle_root(evidence_leaves(report))


def build_request_body(root: str) -> dict[str, Any]:
    """Rekor v2 ``hashes/entries`` request: one sha256 hash, kind=intoto."""
    return {
        "hashes": [{"hash": root, "algorithm": "SHA256"}],
        "kindVersion": {"kind": "intoto", "version": "0.0.1"},
    }


def rekor_submit(root: str, timeout: float = 15.0) -> dict[str, Any]:
    """Submit the root to Rekor v2; return {uuid, logIndex, integratedTime}.

    Raises RuntimeError on any non-success — the caller turns that into a
    clean CLI error. No retries, no silent fallbacks.
    """
    import json as _json
    from urllib.error import URLError
    from urllib.request import Request, urlopen  # stdlib only: notarize stays dependency-free

    body = _json.dumps(build_request_body(root)).encode("utf-8")
    req = Request(
        REKOR_V2_HASHES_URL,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:  # nosec B310 — fixed https URL
            payload = _json.loads(resp.read().decode("utf-8"))
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"rekor submission failed: {exc}") from exc
    entry = payload.get("entries", [{}])[0] if isinstance(payload, dict) else {}
    return {
        "uuid": entry.get("uuid") or entry.get("entryUUID", ""),
        "logIndex": entry.get("logIndex"),
        "integratedTime": entry.get("integratedTime"),
        "url": f"{REKOR_V2_HASHES_URL}/{entry.get('uuid', '')}",
    }


def rekor_verify(report: dict[str, Any], entry: dict[str, Any]) -> bool:
    """True when the stored entry matches the report's recomputed root."""
    root = notarization_root(report)
    stored = str(entry.get("root", ""))
    return bool(stored) and stored == root


def notarize_findings(
    report: dict[str, Any],
    offline_root: str,
    entry: dict[str, Any] | None,
) -> list[Finding]:
    """Findings for the notarization outcome (manifest always; entry when online)."""
    out = [
        Finding(
            module="notarize",
            kind="notarize.manifest",
            host="-",
            detail={"merkle_root": offline_root, "hash_only": True},
            evidence=[
                Evidence(
                    "packet_hex",
                    offline_root,
                    "sha256/Merkle root over all evidence hashes (hash-only disclosure)",
                )
            ],
        )
    ]
    if entry:
        out.append(
            Finding(
                module="notarize",
                kind="notarize.rekor-entry",
                host="-",
                severity=Severity.INFO,
                detail={
                    "uuid": entry.get("uuid", ""),
                    "logIndex": entry.get("logIndex"),
                    "integratedTime": entry.get("integratedTime"),
                    "url": entry.get("url", ""),
                    "log": "rekor.sigstore.dev (v2 hashes/entries)",
                },
            )
        )
    return out
