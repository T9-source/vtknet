"""in-toto Statement v1 attestations over the DSSE pipeline (top-1% form).

``vtk sign --intoto`` wraps the same report the plain signer wraps — but
as an `in-toto Statement <https://in-toto.io/Statement/v1>`_ so standard
verifiers (cosign verify-attestation style consumers, in-toto golang/py
libs) can process it:

- ``_type``: the fixed Statement v1 type URI;
- ``subject``: one ResourceDescriptor per probed host — ``name`` = host,
  ``digest.sha256`` = the sha256 of that host's concatenated evidence
  hashes (hosts are the "artifacts" of a network scan);
- ``predicateType``: ``https://vtknet.dev/attestation/scan-report/v1``;
- ``predicate``: the full report (command, args, stats, findings).

The DSSE envelope is unchanged (same PAE, same ed25519); only the payload
type becomes ``application/vnd.in-toto+json`` — exactly what the
attestation spec prescribes.
"""

from __future__ import annotations

import hashlib
import json
import logging

from vtknet.core.signing import canonical_json, evidence_leaves

log = logging.getLogger("vtknet.intoto")

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://vtknet.dev/attestation/scan-report/v1"
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def subject_digests(report: dict) -> list[dict]:
    """One ResourceDescriptor per probed host, digests over its evidence hashes.

    Spec note (statement.md): a subject MUST carry a digest; the name may
    be unset for scans where the result applies regardless of naming —
    vtknet names subjects by host for human readability.
    """
    per_host: dict[str, list[str]] = {}
    for f in report.get("findings", []):
        host = str(f.get("host", "-"))
        for ev in f.get("evidence", []):
            if isinstance(ev, dict) and ev.get("sha256"):
                per_host.setdefault(host, []).append(ev["sha256"])
    subjects: list[dict] = []
    for host in sorted(per_host):
        joined = "".join(per_host[host]).encode("ascii")
        subjects.append(
            {"name": host, "digest": {"sha256": hashlib.sha256(joined).hexdigest()}}
        )
    if not subjects:  # a report with no evidence still attests over one null subject
        total = hashlib.sha256(canonical_json(report.get("findings", []))).hexdigest()
        subjects = [{"name": "-", "digest": {"sha256": total}}]
    return subjects


def build_statement(report: dict) -> dict:
    """in-toto Statement v1 with the vtknet scan-report predicate."""
    return {
        "_type": STATEMENT_TYPE,
        "subject": subject_digests(report),
        "predicateType": PREDICATE_TYPE,
        "predicate": report,
    }


def statement_leaves(statement: dict) -> list[str]:
    """Merkle leaves of a statement = the predicate report's evidence hashes."""
    return evidence_leaves(statement.get("predicate", {}))


def statement_json(statement: dict) -> str:
    """Canonical JSON text of the statement (sorted keys, stable signing input)."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_statement_envelope(envelope: dict, pub_path: str) -> dict:
    """Verify an in-toto DSSE envelope; return the verified Statement dict.

    Same PAE/ed25519 pipeline as the report signer — only the payloadType
    differs (``application/vnd.in-toto+json``). Fails closed like the
    report verifier: any structural problem or signature mismatch raises.
    """
    import base64

    if not isinstance(envelope, dict) or "payload" not in envelope or "signatures" not in envelope:
        raise ValueError("not a DSSE envelope (missing payload/signatures)")
    payload_type = envelope.get("payloadType", "")
    if payload_type != INTOTO_PAYLOAD_TYPE:
        raise ValueError(f"unexpected payloadType: {payload_type!r}")
    try:
        body = base64.b64decode(envelope["payload"], validate=True)
    except Exception as exc:
        raise ValueError(f"malformed payload base64: {exc}") from exc
    sigs = envelope["signatures"]
    if not isinstance(sigs, list) or not sigs:
        raise ValueError("envelope has no signatures")
    from vtknet.core.signing import _load_public, pae

    pub = _load_public(pub_path)
    last_error: Exception | None = None
    for entry in sigs:
        try:
            sig = base64.b64decode(entry.get("sig", ""), validate=True)
            pub.verify(sig, pae(payload_type, body))
            return json.loads(body)  # verified bytes only
        except Exception as exc:  # noqa: BLE001 — collect, fail closed below
            last_error = exc
    raise ValueError(f"signature verification failed: {last_error}")
