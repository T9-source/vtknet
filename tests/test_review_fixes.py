"""Review-pass fixes: IANA group lock, ServerHello key_share parsing,
bounded link reads, and real PQ classification."""

from __future__ import annotations

import threading
import time

from vtknet.core.converse import link_recv_bounded
from vtknet.core.engine import Engine, EngineConfig
from vtknet.modules import tlsprobe

# -- fixtures ------------------------------------------------------------


def sh_record(selected_group: int | None) -> bytes:
    """Hand-built minimal TLS 1.3 ServerHello record with one key_share."""
    exts = b"\x00\x2b\x00\x03\x02\x03\x04"  # supported_versions: TLS 1.3
    if selected_group is not None:
        ks_entry = selected_group.to_bytes(2, "big") + b"\x00\x20" + b"\x42" * 32
        exts += b"\x00\x33" + len(ks_entry).to_bytes(2, "big") + ks_entry
    body = (
        b"\x02\x00\x00\x00"  # handshake type + length placeholder
        + b"\x03\x03"  # legacy_version
        + b"\x11" * 32  # random
        + b"\x00"  # legacy_session_id (empty)
        + b"\x13\x01"  # cipher TLS_AES_128_GCM_SHA256
        + b"\x00"  # legacy_compression_method
        + len(exts).to_bytes(2, "big")
        + exts
    )
    body = body[:1] + (len(body) - 4).to_bytes(3, "big") + body[4:]
    return b"\x16\x03\x03" + len(body).to_bytes(2, "big") + body


class FakeLink:
    """Duck-typed TCP_client link: scripted chunks, optional permanent hang."""

    def __init__(self, chunks: list[bytes], hang_forever: bool = False) -> None:
        self._chunks = list(chunks)
        self._hang = hang_forever
        self.closed = False
        self.sent: list[bytes] = []

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, *a: object, **kw: object) -> bytes:
        if self._hang:
            threading.Event().wait()  # blocks until the process tears it down
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        self.closed = True


def short_engine() -> Engine:
    return Engine(EngineConfig(timeout=0.3))


# -- the IANA constant must be the real one ------------------------------


def test_mlkem_group_is_the_real_iana_code_point():
    assert tlsprobe.MLKEM768_GROUP == 4588  # decimal, per IANA / RFC 9847
    assert tlsprobe.MLKEM768_GROUP == 0x11EC  # same value in hex — no confusion


def test_pq_hello_prefers_mlkem_and_ships_hybrid_share():
    data = tlsprobe.build_pq_client_hello_bytes(sni="example.com")
    # supported_groups: MLKEM768 first (client preference), then x25519
    assert b"\x11\xec\x00\x1d" in data
    # key_share: ONE 1216-byte hybrid share — ML-KEM-768 ek (1184B) then
    # x25519 (32B), the RFC 10024 / Chrome wire shape
    hybrid_len = (1184 + 32).to_bytes(2, "big")
    assert b"\x11\xec" + hybrid_len in data
    assert len(data) > 1300  # the hybrid share dominates the hello size


# -- ServerHello key_share parsing ---------------------------------------


def test_selected_group_read_back_for_pq():
    assert tlsprobe.parse_serverhello_selected_group(sh_record(0x11EC)) == 0x11EC


def test_selected_group_read_back_for_classical():
    assert tlsprobe.parse_serverhello_selected_group(sh_record(0x001D)) == 0x1D


def test_selected_group_none_without_key_share():
    assert tlsprobe.parse_serverhello_selected_group(sh_record(None)) is None


def test_selected_group_none_on_garbage_and_alerts():
    assert tlsprobe.parse_serverhello_selected_group(b"") is None
    assert tlsprobe.parse_serverhello_selected_group(b"\x00" * 7) is None
    alert = b"\x15\x03\x03\x00\x02\x02\x28"  # fatal handshake_failure
    assert tlsprobe.parse_serverhello_selected_group(alert) is None


# -- real PQ classification over the probe -------------------------------


def test_pq_probe_negotiated_when_server_selects_mlkem():
    link = FakeLink([sh_record(0x11EC)])
    findings, stats = tlsprobe.pq_tls_probe(
        short_engine(), "203.0.113.9", 443, link_factory=lambda ip, port: link
    )
    assert findings[0].kind == "tls.pq.negotiated"
    assert findings[0].detail["pq_confirmed"] is True
    assert findings[0].detail["pq_selected_group"] == "0x11ec"
    assert stats["chunks"] == 1


def test_pq_probe_fallback_when_server_selects_classical():
    link = FakeLink([sh_record(0x001D)])
    findings, _ = tlsprobe.pq_tls_probe(
        short_engine(), "203.0.113.9", 443, link_factory=lambda ip, port: link
    )
    assert findings[0].kind == "tls.pq.fallback"
    assert findings[0].detail["pq_confirmed"] is False
    assert findings[0].detail["pq_selected_group"] == "0x001d"


def test_pq_probe_alert_still_classified_low():
    link = FakeLink([b"\x15\x03\x03\x00\x02\x02\x28"])
    findings, _ = tlsprobe.pq_tls_probe(
        short_engine(), "203.0.113.9", 443, link_factory=lambda ip, port: link
    )
    assert findings[0].kind == "tls.pq.alert"
    assert findings[0].severity.value == "low"


def test_pq_probe_bounded_on_silent_server():
    started = time.monotonic()
    link = FakeLink([], hang_forever=True)
    findings, _ = tlsprobe.pq_tls_probe(
        short_engine(), "203.0.113.9", 443, link_factory=lambda ip, port: link
    )
    elapsed = time.monotonic() - started
    assert findings[0].kind == "tls.pq.no-response"
    assert elapsed < 5.0  # bounded by engine timeout, not hung forever


# -- bounded link reads ---------------------------------------------------


def test_link_recv_bounded_returns_data():
    assert link_recv_bounded(FakeLink([b"\x16\x03"]), 1.0) == b"\x16\x03"


def test_link_recv_bounded_returns_empty_on_error():
    class BadLink:
        def recv(self):
            raise RuntimeError("boom")

        def close(self):
            pass

    assert link_recv_bounded(BadLink(), 1.0) == b""


def test_link_recv_bounded_times_out_and_closes():
    started = time.monotonic()
    link = FakeLink([], hang_forever=True)
    assert link_recv_bounded(link, 0.3) == b""
    elapsed = time.monotonic() - started
    assert link.closed is True
    assert elapsed < 5.0
