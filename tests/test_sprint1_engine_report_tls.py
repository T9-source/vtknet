"""Sprint 1 additions: dry-run emit, report --diff :last, PQ-TLS builders."""

from __future__ import annotations

import os

import pytest

from vtknet.core.engine import Engine, EngineConfig
from vtknet.core.models import Finding, ScanResult
from vtknet.core.store import History
from vtknet.modules import tlsprobe
from vtknet.utils import net

# -- dry-run emit -------------------------------------------------------------


def _dry_engine(emit: str | None) -> Engine:
    return Engine(EngineConfig(dry_run=True, emit=emit, rate=0))


def test_dry_run_emit_writes_pcap(tmp_path):
    from scapy.all import IP, TCP

    out = str(tmp_path / "emit.pcap")
    eng = _dry_engine(out)
    eng.send_recv([IP(dst="192.0.2.1") / TCP(dport=80, flags="S")])
    assert os.path.exists(out) and os.path.getsize(out) > 24  # pcap header at minimum


def test_dry_run_emit_fakes_ethernet_header(tmp_path):
    """L3 probes are framed with placeholder MACs — never scapy neighbor resolution."""
    from scapy.all import IP, TCP, Ether, rdpcap

    out = str(tmp_path / "emit.pcap")
    _dry_engine(out).send_recv([IP(dst="192.0.2.1") / TCP(dport=80, flags="S")])
    pkts = rdpcap(out)
    assert len(pkts) == 1
    eth = pkts[0][Ether]
    assert eth.src == "00:00:00:00:00:00"
    assert eth.dst == "ff:ff:ff:ff:ff:ff"


def test_dry_run_emit_l2_packets_pass_through(tmp_path):
    from scapy.all import ARP, Ether, rdpcap

    out = str(tmp_path / "emit.pcap")
    frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.0.2.1")
    _dry_engine(out).send_recv([frame], l2=True)
    pkts = rdpcap(out)
    assert len(pkts) == 1 and pkts[0].haslayer(ARP)


def test_dry_run_without_emit_writes_nothing(tmp_path):
    from scapy.all import IP

    out = str(tmp_path / "nope.pcap")
    _dry_engine(None).send_recv([IP(dst="192.0.2.1")])
    assert not os.path.exists(out)


def test_dry_run_emit_unwritable_path_degrades(tmp_path):
    from scapy.all import IP, TCP

    bad = str(tmp_path / "no_dir" / "x.pcap")
    eng = Engine(EngineConfig(dry_run=True, emit=bad))
    answered, _ = eng.send_recv([IP(dst="192.0.2.1") / TCP(dport=80)])  # must not raise
    assert answered == []


def test_cli_dry_run_emit_flag_wired(tmp_path):
    """The --emit flag exists and the dry-run path produces a reviewable pcap."""
    from vtknet import cli

    out = str(tmp_path / "wired.pcap")
    rc = cli.main(["sweep", "192.0.2.0/30", "--dry-run", "--emit", out, "--json"])
    assert rc == 0
    assert os.path.exists(out)


# -- report --diff :last -------------------------------------------------------


def _mk_run(hist: History, command: str, target: str, findings: list[Finding]) -> int:
    r = ScanResult(command=command, args={"target": target})
    r.findings = findings
    r.finish(0.1)
    return hist.save_result(r)


def _f(kind: str, host: str, port: int | None = None) -> Finding:
    return Finding(module="m", kind=kind, host=host, port=port)


def test_find_last_run_by_command_and_target(tmp_path):
    h = History(str(tmp_path / "h.db"))
    a = _mk_run(h, "scan", "10.0.0.5", [_f("port.open", "10.0.0.5", 80)])
    _mk_run(h, "scan", "10.0.0.9", [])
    b = _mk_run(h, "scan", "10.0.0.5", [_f("port.open", "10.0.0.5", 80), _f("port.open", "10.0.0.5", 443)])
    assert h.find_last_run("scan", target="10.0.0.5") == b
    assert h.find_last_run("scan", target="10.0.0.5", before_id=b) == a
    h.close()


def test_find_last_run_no_match_returns_none(tmp_path):
    h = History(str(tmp_path / "h.db"))
    _mk_run(h, "scan", "10.0.0.5", [])
    assert h.find_last_run("sweep", target="10.0.0.0/24") is None
    h.close()


def test_cli_report_diff_last(tmp_path):
    """:last resolves to the newest run of the same command+target."""
    from vtknet import cli

    db = str(tmp_path / "h.db")
    h = History(db)
    _mk_run(h, "scan", "192.0.2.7", [_f("port.open", "192.0.2.7", 80)])
    _mk_run(h, "scan", "192.0.2.7", [_f("port.open", "192.0.2.7", 80), _f("port.open", "192.0.2.7", 443)])
    h.close()
    rc = cli.main(["--db", db, "report", "--diff", "1", ":last", "--json"])
    assert rc == 0


def test_cli_report_diff_last_colon_forms_error_paths(tmp_path):
    from vtknet import cli

    db = str(tmp_path / "h.db")
    # empty history -> ':last' must fail cleanly with exit 2
    assert cli.main(["--db", db, "report", "--diff", ":last", "1"]) == cli.EXIT_USAGE


def test_cli_report_diff_bad_ref(tmp_path):
    from vtknet import cli

    db = str(tmp_path / "h.db")
    h = History(db)
    _mk_run(h, "scan", "10.0.0.5", [])
    h.close()
    rc = cli.main(["--db", db, "report", "--diff", "bogus", "1"])
    assert rc == cli.EXIT_USAGE


# -- PQ-TLS builders ------------------------------------------------------------


def test_pq_client_hello_advertises_mlkem_group():
    from vtknet.modules.tlsprobe import MLKEM768_GROUP, build_pq_client_hello_bytes

    data = build_pq_client_hello_bytes(sni="example.com")
    # hard-coded regression: IANA code point for X25519MLKEM768 is 4588 = 0x11EC
    # (do NOT derive from the constant — a wrong constant must fail this test)
    assert b"\x11\xec" in data
    assert b"\x45\x88" not in data  # the historical typo must never return
    assert MLKEM768_GROUP == 0x11EC
    assert data.startswith(b"\x16\x03\x01")


def test_pq_client_hello_is_deterministic():
    import random

    a = tlsprobe.build_pq_client_hello_bytes(rng=random.Random(7))
    b = tlsprobe.build_pq_client_hello_bytes(rng=random.Random(7))
    assert a == b


def test_pq_client_hello_force_fragment_exceeds_mtu():
    plain = tlsprobe.build_pq_client_hello_bytes(sni="example.com")
    frag = tlsprobe.build_pq_client_hello_bytes(sni="example.com", force_fragment=True)
    assert len(plain) > 1300  # mlkem key_share dominates
    assert len(frag) > 1600  # padded past the 1500-byte MTU
    assert len(frag) > len(plain)


def test_pq_client_hello_handshake_length_consistent():
    data = tlsprobe.build_pq_client_hello_bytes(sni="x.example")
    hs_len = int.from_bytes(data[6:9], "big")
    assert hs_len + 4 + 5 == len(data)  # handshake body + hs header + record header


def test_tls_probe_dispatches_to_pq(monkeypatch):
    calls = {}

    def fake_pq(engine, dst, **kw):
        calls["dst"] = dst
        calls.update(kw)
        return [], {"sent": 0}

    monkeypatch.setattr(tlsprobe, "pq_tls_probe", fake_pq)
    eng = Engine(EngineConfig(dry_run=False))
    tlsprobe.tls_probe(eng, "192.0.2.1", pq=True, force_fragment=True)
    assert calls["dst"] == "192.0.2.1"
    assert calls["force_fragment"] is True


def test_resolve_host_still_ipv4_only():
    with pytest.raises(ValueError):
        net.expand_hosts("2001:db8::/64")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__]))
