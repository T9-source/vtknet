"""DSSE-signed scan reports (Ed25519) — the end of the chain of custody.

Implements DSSE v1 exactly (https://github.com/secure-systems-lab/dsse):

    PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type
                    + SP + LEN(body) + SP + body

The signature covers the PAE bytes — never the raw payload. The payload
type is the application-specific ``application/vnd.vtknet.report.v1+json``
(DSSE forbids generic types). Verification fails closed: any structural
problem, bad base64, or bad signature raises ValueError — a failed check
means the report is untrusted, not "probably fine".

Design (per the cosign/in-toto attestation model): the report stays a
readable JSON file; the envelope (``report.json.dsse``) is a detachable
sidecar. ``sign`` is reproducible: canonical JSON serialization (sorted
keys, no spaces) means the same findings always produce the same signed
bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PublicFormat,
)

log = logging.getLogger("vtknet.signing")

VTKNET_PAYLOAD_TYPE = "application/vnd.vtknet.report.v1+json"
DEFAULT_KEYS_DIR = Path.home() / ".vtknet" / "keys"


# -- primitives -----------------------------------------------------------


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 Pre-Authentication Encoding — the exact bytes that get signed."""
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type.encode("utf-8")
        + b" "
        + str(len(body)).encode("ascii")
        + b" "
        + body
    )


def canonical_json(obj: object) -> bytes:
    """Stable serialization: same findings => same bytes => same signature."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


# -- keys -------------------------------------------------------------------


def keygen(out_dir: str | Path = DEFAULT_KEYS_DIR) -> tuple[Path, Path, str]:
    """Generate an Ed25519 keypair; returns (private_path, public_path, keyid).

    The keyid (hex sha256 of the DER public key) is an unauthenticated hint
    per DSSE — verification always uses the trusted public key file itself.
    Private keys land with mode 0600.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    pub_der = sk.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    keyid = hashlib.sha256(pub_der).hexdigest()[:16]
    priv_path = out / f"{keyid}.key"
    pub_path = out / f"{keyid}.pub"
    priv_path.write_bytes(
        sk.private_bytes(
            Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            NoEncryption(),  # v1: unencrypted on disk; disk-level secrecy is the operator's
        )
    )
    priv_path.chmod(0o600)
    pub_path.write_bytes(sk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    log.info("keypair generated: %s (+ .pub), keyid=%s", priv_path, keyid)
    return priv_path, pub_path, keyid


def _load_private(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        # ValueError on purpose: the CLI maps it to a clean usage error
        raise ValueError(f"not an Ed25519 private key: {path}")  # noqa: TRY004
    return key


def _load_public(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"not an Ed25519 public key: {path}")  # noqa: TRY004
    return key


# -- envelope -----------------------------------------------------------------


def sign_report(report: dict, key_path: str | Path) -> dict:
    """Wrap one report in a DSSE v1 envelope signed with the given key."""
    body = canonical_json(report)
    sk = _load_private(key_path)
    pub = sk.public_key()
    keyid = hashlib.sha256(
        pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()[:16]
    sig = sk.sign(pae(VTKNET_PAYLOAD_TYPE, body))
    return {
        "payload": base64.b64encode(body).decode("ascii"),
        "payloadType": VTKNET_PAYLOAD_TYPE,
        "vtknetMerkleRoot": merkle_root(evidence_leaves(report)),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def verify_envelope(envelope: dict, pub_path: str | Path) -> bytes:
    """Verify a DSSE envelope against a trusted public key; return the body.

    Fails closed (ValueError) on any structural problem or signature
    mismatch. Returns the exact verified payload bytes — callers must use
    THESE bytes for the application layer, never re-parse the envelope.
    """
    if not isinstance(envelope, dict) or "payload" not in envelope or "signatures" not in envelope:
        raise ValueError("not a DSSE envelope (missing payload/signatures)")
    payload_type = envelope.get("payloadType", "")
    if payload_type != VTKNET_PAYLOAD_TYPE:
        raise ValueError(f"unexpected payloadType: {payload_type!r}")
    try:
        body = base64.b64decode(envelope["payload"], validate=True)
    except Exception as exc:
        raise ValueError(f"malformed payload base64: {exc}") from exc
    sigs = envelope["signatures"]
    if not isinstance(sigs, list) or not sigs:
        raise ValueError("envelope has no signatures")
    pub = _load_public(pub_path)
    last_error: Exception | None = None
    for entry in sigs:
        try:
            sig = base64.b64decode(entry.get("sig", ""), validate=True)
            pub.verify(sig, pae(payload_type, body))
            return body  # first good signature wins (multi-sig thresholds later)
        except Exception as exc:  # noqa: BLE001 — collect and fail closed below
            last_error = exc
    raise ValueError(f"signature verification failed: {last_error}")


def is_envelope(obj: object) -> bool:
    """True when the parsed object looks like a vtknet DSSE envelope."""
    return (
        isinstance(obj, dict)
        and "payloadType" in obj
        and "signatures" in obj
        and "payload" in obj
    )


# -- Merkle-ized findings: selective disclosure ------------------------------
#
# The envelope carries a Merkle root over every evidence hash in the report
# (``vtknetMerkleRoot`` — unknown envelope fields are ignored by DSSE
# consumers, ours use it). A single finding can then be handed to a third
# party WITH an inclusion proof, without disclosing the rest of the report
# — Certificate-Transparency style. Convention: the last leaf is duplicated
# when a level has an odd count.


def evidence_leaves(report: dict) -> list[str]:
    """Ordered evidence sha256 hex strings of a report (the Merkle leaves)."""
    leaves: list[str] = []
    for f in report.get("findings", []):
        for ev in f.get("evidence", []):
            if isinstance(ev, dict) and ev.get("sha256"):
                leaves.append(ev["sha256"])
    return leaves


def merkle_root(leaves: list[str]) -> str:
    """Merkle root over sha256-hex leaves; empty tree hashes a fixed tag."""
    if not leaves:
        return hashlib.sha256(b"vtknet:no-evidence").hexdigest()
    level = [bytes.fromhex(h) for h in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def merkle_proof(leaves: list[str], index: int) -> list[str]:
    """Sibling hashes bottom-up for ``leaves[index]`` (odd levels duplicate last)."""
    if not 0 <= index < len(leaves):
        raise ValueError(f"leaf index out of range: {index} of {len(leaves)}")
    level = [bytes.fromhex(h) for h in leaves]
    proof: list[str] = []
    i = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = i + 1 if i % 2 == 0 else i - 1
        proof.append(level[sibling].hex())
        level = [
            hashlib.sha256(level[j] + level[j + 1]).digest()
            for j in range(0, len(level), 2)
        ]
        i //= 2
    return proof


def merkle_verify(leaf: str, proof: list[str], root: str, index: int) -> bool:
    """Recompute the root from one leaf + its proof — the inclusion check."""
    node = bytes.fromhex(leaf)
    for sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        node = (
            hashlib.sha256(node + sibling).digest()
            if index % 2 == 0
            else hashlib.sha256(sibling + node).digest()
        )
        index //= 2
    return node.hex() == root


def finding_inclusion_proof(report: dict, finding_id: str) -> dict | None:
    """Selective-disclosure package for one finding: leaf + proof + root.

    Returns None when the finding (or its evidence) is not in the report.
    """
    leaves = evidence_leaves(report)
    if not leaves:
        return None
    for pos, f in enumerate(report.get("findings", [])):
        if str(f.get("id")) != finding_id:
            continue
        evs = [ev for ev in f.get("evidence", []) if isinstance(ev, dict) and ev.get("sha256")]
        if not evs:
            return None
        # global index of this finding's first evidence leaf
        before = sum(
            1
            for g in report["findings"][:pos]
            for ev in g.get("evidence", [])
            if isinstance(ev, dict) and ev.get("sha256")
        )
        idx = before
        return {
            "finding_id": finding_id,
            "leaf": leaves[idx],
            "index": idx,
            "proof": merkle_proof(leaves, idx),
            "root": merkle_root(leaves),
            "verified": merkle_verify(leaves[idx], merkle_proof(leaves, idx), merkle_root(leaves), idx),
        }
    return None
