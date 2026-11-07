import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vtknet.core.engine import EngineConfig
from vtknet.modules.tlsprobe import (
    certificate_findings,
    extract_certificates,
    summarize_certificate,
    tls_probe,
)

_CN = "lab.local"


def _make_cert(days: int) -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=61 if days < 0 else 1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .public_key(key.public_key())
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _cert_record(der: bytes) -> bytes:
    chain = len(der).to_bytes(3, "big") + der
    body = len(chain).to_bytes(3, "big") + chain
    hs = b"\x0b" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _server_hello_record() -> bytes:
    payload = (
        (0x0303).to_bytes(2, "big")
        + b"\x11" * 32
        + b"\x00"
        + (0xC02F).to_bytes(2, "big")
        + b"\x00"
        + (0).to_bytes(2, "big")
    )
    hs = b"\x02" + len(payload).to_bytes(3, "big") + payload
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


class ExtractTest(unittest.TestCase):
    def test_extract_from_mixed_record_stream(self):
        der = _make_cert(60)
        stream = _server_hello_record() + _cert_record(der)
        certs = extract_certificates(stream)
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0], der)

    def test_garbage_yields_nothing(self):
        self.assertEqual(extract_certificates(b"\x00" * 64), [])
        self.assertEqual(extract_certificates(b""), [])


class SummarizeTest(unittest.TestCase):
    def test_fresh_self_signed_cert(self):
        der = _make_cert(60)
        info = summarize_certificate(der)
        self.assertIn(_CN, info["subject"])
        self.assertIn(_CN, info["issuer"])
        self.assertTrue(info["self_signed"])
        self.assertGreaterEqual(info["days_left"], 58)
        self.assertEqual(info["sans"], [])

    def test_findings_severity_by_expiry(self):
        fresh = certificate_findings("203.0.113.9", 443, [_make_cert(60)])
        expired = certificate_findings("203.0.113.9", 443, [_make_cert(-1)])
        self.assertEqual(fresh[0].kind, "tls.certificate")
        self.assertEqual(fresh[0].severity.value, "info")
        self.assertEqual(expired[0].kind, "tls.cert.expired")
        self.assertEqual(expired[0].severity.value, "high")
        self.assertLess(expired[0].detail["days_left"], 0)

    def test_malformed_cert_is_skipped_not_raised(self):
        findings = certificate_findings("203.0.113.9", 443, [b"\xde\xad\xbe\xef"])
        self.assertEqual(findings, [])


class _FakeEngine:
    """Engine duck-type: tls_probe only reads cfg (dry_run)."""

    def __init__(self) -> None:
        self.cfg = EngineConfig()


class _FakeLink:
    """Duck-typed TCP_client supersocket: yields canned flight chunks."""

    def __init__(self, chunks) -> None:
        self._chunks = list(chunks)
        self.sent = None
        self.closed = False

    def send(self, data) -> None:
        self.sent = bytes(data)

    def recv(self):
        return self._chunks.pop(0) if self._chunks else None

    def close(self) -> None:
        self.closed = True


class ProbeFlowTest(unittest.TestCase):
    def test_probe_returns_serverhello_and_certificate(self):
        chunks = [_server_hello_record(), _cert_record(_make_cert(60))]
        fake = _FakeLink(chunks)
        findings, stats = tls_probe(
            _FakeEngine(),
            "203.0.113.9",
            443,
            sni="lab.local",
            link_factory=lambda ip, port: fake,
        )
        kinds = [f.kind for f in findings]
        self.assertEqual(kinds[0], "tls.serverhello")
        self.assertEqual(kinds[1], "tls.certificate")
        self.assertEqual(stats["chunks"], 2)
        self.assertTrue(fake.closed)
        self.assertEqual(fake.sent[:1], b"\x16")  # a TLS handshake record went out

    def test_no_data_yields_no_data_finding(self):
        fake = _FakeLink([])
        findings, stats = tls_probe(
            _FakeEngine(), "203.0.113.9", 443, link_factory=lambda ip, port: fake
        )
        self.assertEqual(findings[0].kind, "tls.no-data")
        self.assertEqual(stats["chunks"], 0)
        self.assertTrue(fake.closed)

    def test_connect_failure_yields_no_response(self):
        def broken_factory(ip, port):
            raise OSError("no route")

        findings, stats = tls_probe(
            _FakeEngine(), "203.0.113.9", 443, link_factory=broken_factory
        )
        self.assertEqual(findings[0].kind, "tls.no-response")
        self.assertEqual(stats["sent"], 0)

    def test_dry_run_never_invokes_factory(self):
        eng = _FakeEngine()
        eng.cfg = EngineConfig(dry_run=True)
        called = []
        findings, stats = tls_probe(
            eng,
            "203.0.113.9",
            443,
            link_factory=lambda ip, port: called.append(1) or _FakeLink([]),
        )
        self.assertEqual(findings, [])
        self.assertEqual(stats["sent"], 0)
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
