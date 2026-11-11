"""Sprint 2/3/5 expansion: ECH, IDS eval, deep verify, in-toto, notarize, watch, minimize."""

from __future__ import annotations

import json
import random

import pytest

from vtknet.core.kinds import SCHEMA_VERSION, get_kind, kinds_schema
from vtknet.core.models import Finding, ScanResult

# ---------------------------------------------------------------- ECH probing


def test_grease_extension_shape():
    from vtknet.modules.echprobe import ECH_EXT_TYPE, build_grease_ech_extension

    rng = random.Random(7)
    ext = build_grease_ech_extension(rng)
    assert int.from_bytes(ext[0:2], "big") == ECH_EXT_TYPE  # 0xFE0D
    # ext = type(2) + ext_len(2) + body; body = version(2) + config_id(1) + blen(2) + blob
    ext_len = int.from_bytes(ext[2:4], "big")
    body = ext[4:]
    assert len(body) == ext_len
    blen = int.from_bytes(body[3:5], "big")
    assert len(body) == 5 + blen and 16 <= blen <= 31


def test_grease_client_hello_is_deterministic_and_valid():
    from vtknet.modules.echprobe import build_grease_client_hello_bytes

    a = build_grease_client_hello_bytes(sni="example.com", rng=random.Random(3))
    b = build_grease_client_hello_bytes(sni="example.com", rng=random.Random(3))
    assert a == b
    assert a.startswith(b"\x16\x03\x01")
    # handshake length framing still intact after the splice
    hs_len = int.from_bytes(a[6:9], "big")
    assert hs_len + 4 + 5 == len(a)


def test_classify_ech_required_alert():
    from vtknet.modules.echprobe import classify_reply

    alert = b"\x15\x03\x03\x00\x02\x02\x79"  # fatal(2) ech_required(121)
    assert classify_reply(alert)["kind"] == "tls.alert.ech-required"
    hf = b"\x15\x03\x03\x00\x02\x02\x28"  # handshake_failure(40)
    assert classify_reply(hf)["kind"] == "tls.alert.handshake-failure"
    assert classify_reply(b"\x00\x01")["kind"] == "tls.other"


def test_https_record_ech_parsing():
    from vtknet.modules.echprobe import parse_https_record_ech

    hit = parse_https_record_ech("1 . alpn=h2 ech=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    assert hit and hit["ech_present"] is True
    assert parse_https_record_ech("1 . alpn=h2 ipv4hint=192.0.2.1") is None


def test_ech_probe_dry_run_and_registry():
    from vtknet.core.engine import Engine, EngineConfig
    from vtknet.modules.echprobe import ech_probe

    eng = Engine(EngineConfig(dry_run=True))
    findings, stats = ech_probe(eng, "example.com")
    assert findings == [] and stats == {"sent": 0}
    for k in ("ech.dns.config-found", "ech.enforced", "ech.path.tolerant"):
        assert get_kind(k) is not None


def test_ech_greased_probe_fakes():
    from vtknet.core.engine import Engine, EngineConfig
    from vtknet.modules import echprobe

    class FakeLink:
        def __init__(self, data: bytes) -> None:
            self.data = data
            self.sent: list[bytes] = []

        def send(self, b: bytes) -> None:
            self.sent.append(b)

        def recv(self) -> bytes:
            return self.data

        def close(self) -> None:
            pass

    eng = Engine(EngineConfig(timeout=0.3))
    # ServerHello answer -> tolerant
    link = FakeLink(b"\x16\x03\x03\x00\x2a" + b"\x00" * 42)
    f, _ = echprobe.greased_ech_probe(eng, "203.0.113.5", link_factory=lambda i, p: link)
    assert f[0].kind == "ech.path.tolerant"
    # ech_required alert -> enforced (HIGH)
    link = FakeLink(b"\x15\x03\x03\x00\x02\x02\x79")
    f, _ = echprobe.greased_ech_probe(eng, "203.0.113.5", link_factory=lambda i, p: link)
    assert f[0].kind == "ech.enforced" and f[0].severity.value == "high"
    # handshake_failure -> intolerant (MEDIUM)
    link = FakeLink(b"\x15\x03\x03\x00\x02\x02\x28")
    f, _ = echprobe.greased_ech_probe(eng, "203.0.113.5", link_factory=lambda i, p: link)
    assert f[0].kind == "ech.path.intolerant" and f[0].severity.value == "medium"


# ---------------------------------------------------------------- IDS eval


def test_eval_scoring_matrix():
    from vtknet.modules.idseval import score

    s = score("tcp_scan", ["ET SCAN Suricata Portscan"], {"target": "192.0.2.9"})
    assert s["detected"] and s["keyword_hits"]
    s2 = score("tcp_scan", [], {"target": "192.0.2.9"})
    assert not s2["detected"] and s2["verdict"] == "missed"


def test_eval_null_engine_end_to_end(tmp_path):
    from vtknet.modules.idseval import eval_scenario

    findings, stats = eval_scenario(
        "tcp_scan", str(tmp_path), engine="null", extra={"null_alerts": ["ET SCAN portscan"]}, count=5
    )
    assert findings[0].kind == "eval.detected"
    assert stats["detected"] == 1
    # sidecar + pcap written
    assert (tmp_path / "tcp_scan.pcap").exists()
    side = json.loads((tmp_path / "tcp_scan.pcap.json").read_text())
    assert side["name"] == "tcp_scan"


def test_eval_missed_is_high(tmp_path):
    from vtknet.modules.idseval import eval_scenario

    findings, _ = eval_scenario("tcp_scan", str(tmp_path), engine="null", extra={"null_alerts": []}, count=5)
    assert findings[0].kind == "eval.missed" and findings[0].severity.value == "high"


def test_eval_unknown_engine_raises(tmp_path):
    from vtknet.modules.idseval import eval_scenario

    with pytest.raises(ValueError):
        eval_scenario("tcp_scan", str(tmp_path), engine="snort3")


# ---------------------------------------------------------------- deep verify


def _report_with_port_open_reply() -> dict:
    # minimal Ether+IPv4+TCP SYN-ACK reply frame (hand-built)
    eth = b"\x00" * 12 + b"\x08\x00"
    ip = b"\x45\x00\x00\x28" + b"\x00\x01\x00\x00\x40\x06\x00\x00" + b"\xc0\x00\x02\x05" + b"\xc0\x00\x02\x09"
    tcp = b"\x00\x50" + b"\x1f\x90" + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x02" + b"\x50\x02" + b"\x71\x10" + b"\x00\x00\x00\x00"
    frame = eth + ip + tcp
    return {
        "command": "scan",
        "findings": [
            {
                "id": "abc123",
                "kind": "port.open",
                "host": "192.0.2.9",
                "port": 8080,
                "severity": "info",
                "evidence": [
                    {"kind": "packet_hex", "data": frame.hex(), "note": "syn reply", "sha256": __import__("hashlib").sha256(frame.hex().encode()).hexdigest()}
                ],
            }
        ],
    }


def test_deep_verify_holds_on_synack():
    from vtknet.core.verifydeep import verify_report_deep

    report = _report_with_port_open_reply()
    # set flags byte (tcp_off+13 = 47) to SYN+ACK
    ev = report["findings"][0]["evidence"][0]
    raw = bytearray(bytes.fromhex(ev["data"]))
    raw[47] = 0x12
    ev["data"] = bytes(raw).hex()
    ev["sha256"] = __import__("hashlib").sha256(ev["data"].encode()).hexdigest()
    findings, stats = verify_report_deep(report)
    deeps = [f for f in findings if f.kind.startswith("verify.deep")]
    assert any(f.kind == "verify.deep.holds" for f in deeps)
    assert stats["deep_holds"] >= 1


def test_deep_verify_contradicts_on_rst():
    from vtknet.core.verifydeep import verify_report_deep

    report = _report_with_port_open_reply()
    ev = report["findings"][0]["evidence"][0]
    raw = bytearray(bytes.fromhex(ev["data"]))
    raw[47] = 0x04  # RST only — contradicts a port.open claim
    ev["data"] = bytes(raw).hex()
    ev["sha256"] = __import__("hashlib").sha256(ev["data"].encode()).hexdigest()
    findings, stats = verify_report_deep(report)
    assert stats["deep_contradicts"] == 1
    assert any(f.kind == "verify.deep.contradicts" for f in findings)


def test_deep_verify_skips_unknown_evidence():
    from vtknet.core.verifydeep import verify_report_deep

    report = {
        "command": "x",
        "findings": [
            {"id": "1", "kind": "host.alive", "host": "h", "severity": "info",
             "evidence": [{"kind": "pcap", "data": "/tmp/x.pcap", "note": ""}]}
        ],
    }
    _findings, stats = verify_report_deep(report)
    assert stats["deep_skipped"] >= 1  # pcap evidence is not deep-checkable


# ---------------------------------------------------------------- in-toto


def test_intoto_statement_shape():
    from vtknet.core.intoto import PREDICATE_TYPE, STATEMENT_TYPE, build_statement

    report = {
        "command": "scan",
        "findings": [
            {"id": "1", "kind": "port.open", "host": "h1", "severity": "info",
             "evidence": [{"kind": "packet_hex", "data": "aabb", "sha256": "aa" * 32}]},
            {"id": "2", "kind": "port.open", "host": "h1", "severity": "info",
             "evidence": [{"kind": "packet_hex", "data": "ccdd", "sha256": "bb" * 32}]},
            {"id": "3", "kind": "host.alive", "host": "h2", "severity": "info",
             "evidence": [{"kind": "packet_hex", "data": "eeff", "sha256": "cc" * 32}]},
        ],
    }
    st = build_statement(report)
    assert st["_type"] == STATEMENT_TYPE
    assert st["predicateType"] == PREDICATE_TYPE
    assert st["predicate"] is report
    hosts = {s["name"] for s in st["subject"]}
    assert hosts == {"h1", "h2"}
    for s in st["subject"]:
        assert "sha256" in s["digest"] and len(s["digest"]["sha256"]) == 64


def test_intoto_sign_and_verify_roundtrip(tmp_path):
    from vtknet.core import signing as signing_mod
    from vtknet.core.intoto import (
        INTOTO_PAYLOAD_TYPE,
        build_statement,
        verify_statement_envelope,
    )

    priv, pub, keyid = signing_mod.keygen(tmp_path / "keys")
    report = {"command": "scan", "findings": [], "stats": {}}
    statement = build_statement(report)
    body = signing_mod.canonical_json(statement)
    sk = signing_mod._load_private(priv)
    env = {
        "payload": __import__("base64").b64encode(body).decode(),
        "payloadType": INTOTO_PAYLOAD_TYPE,
        "signatures": [
            {
                "keyid": keyid,
                "sig": __import__("base64")
                .b64encode(sk.sign(signing_mod.pae(INTOTO_PAYLOAD_TYPE, body)))
                .decode(),
            }
        ],
    }
    verified = verify_statement_envelope(env, pub)
    assert verified["_type"] == "https://in-toto.io/Statement/v1"
    # a tampered payload must fail closed
    tampered = dict(env)
    tampered["payload"] = __import__("base64").b64encode(b"{\"x\":1}").decode()
    with pytest.raises(ValueError):
        verify_statement_envelope(tampered, pub)


# ---------------------------------------------------------------- notarize


def test_notarize_manifest_offline():
    from vtknet.core.notarize import notarization_root, notarize_findings

    report = {"command": "c", "findings": [
        {"id": "1", "kind": "k", "host": "h", "severity": "info",
         "evidence": [{"kind": "packet_hex", "data": "aabb", "sha256": "dd" * 32}]}
    ]}
    root = notarization_root(report)
    assert len(root) == 64
    f = notarize_findings(report, root, None)
    assert f[0].kind == "notarize.manifest" and f[0].detail["merkle_root"] == root


def test_notarize_request_body_shape():
    from vtknet.core.notarize import build_request_body

    body = build_request_body("ab" * 32)
    assert body["hashes"][0]["algorithm"] == "SHA256"
    assert body["kindVersion"]["kind"] == "intoto"


# ---------------------------------------------------------------- watch


def test_watch_profile_round_argv_and_diff(tmp_path):
    from vtknet.core.store import History
    from vtknet.core.watch import diff_rounds, round_argv

    argv = round_argv("sweep", {"target": "192.168.1.0/24", "json": True})
    assert argv == ["--target", "192.168.1.0/24", "--json"]

    h = History(str(tmp_path / "w.db"))

    def mk(hosts, cidr="10.0.0.0/24"):
        r = ScanResult(command="sweep", args={"target": cidr})
        r.findings = [Finding(module="recon", kind="host.alive", host=h_) for h_ in hosts]
        r.finish(0.01)
        return h.save_result(r)

    a = mk(["10.0.0.1"])
    b = mk(["10.0.0.1", "10.0.0.99"])
    changes = diff_rounds(h, a, b, min_severity="low")
    assert any(c.kind == "watch.added" and c.host == "10.0.0.99" for c in changes)
    h.close()


def test_watch_profile_load_and_default(tmp_path):
    from vtknet.core.watch import load_profile

    p = load_profile(None)
    assert p["rounds"] and p["interval_s"] > 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "x"}))  # no 'rounds' → ValueError
    with pytest.raises(ValueError):
        load_profile(str(bad))


# ---------------------------------------------------------------- minimize


def test_minimize_removes_fields_with_fake_refire():
    from scapy.all import IP, TCP

    from vtknet.core.minimize import minimize_crash

    base = IP(dst="192.0.2.9") / TCP(dport=80, flags="PA")
    crashing = IP(dst="192.0.2.9") / TCP(dport=80, flags="PA", urgptr=65535, window=1)

    def refire(trial: Packet) -> bool:  # noqa: F821
        # pretend the crash only needs dport+flags: any packet with them still "crashes"
        t = trial[TCP]
        return t.dport == 80 and t.flags == "PA"

    m = minimize_crash(crashing, base, refire)
    assert "urgptr" in m["removed"] and "window" in m["removed"]
    assert m["packet"][TCP].urgptr == base[TCP].urgptr


def test_minimize_reproducible_from_seed():
    from vtknet.modules import fuzz as fuzzmod

    base = fuzzmod._base_packet("192.0.2.9", "tcp", 80, random.Random(99))
    v1 = list(fuzzmod.fuzz_variants(base, 3, 99))
    v2 = list(fuzzmod.fuzz_variants(base, 3, 99))
    assert [bytes(x) for x in v1] == [bytes(x) for x in v2]


# ---------------------------------------------------------------- schema version


def test_schema_version_in_payload_and_schema():
    r = ScanResult(command="c")
    doc = json.loads(r.to_json())
    assert doc["schema_version"] == SCHEMA_VERSION
    schema = kinds_schema()
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    assert "schema_version" in schema["required"]
    # SCHEMA_VERSION is SemVer
    parts = SCHEMA_VERSION.split(".")
    assert len(parts) == 3 and all(p.isdigit() for p in parts)


def test_new_sprint_kinds_registered():
    for k in ("eval.missed", "watch.changed", "notarize.rekor-entry", "fuzz.minimized",
              "verify.deep.holds", "verify.deep.contradicts", "ech.enforced"):
        assert get_kind(k) is not None, f"missing kind: {k}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__]))
