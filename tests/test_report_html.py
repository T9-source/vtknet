import json
import os
import tempfile
import unittest

from vtknet.core.models import Evidence, Finding, ScanResult, Severity
from vtknet.core.report import render_html, write_html


def _sample_result() -> ScanResult:
    r = ScanResult(command="scan", args={"target": "10.0.0.5", "scan_type": "syn"})
    r.findings = [
        Finding(
            module="scanner",
            kind="port.open",
            host="10.0.0.5",
            port=443,
            state="open",
            severity=Severity.INFO,
            detail={"flags": "SA", "note": "<script>alert(1)</script>"},
            evidence=[Evidence("packet_hex", "45" * 64, "syn/ack")],
        ),
        Finding(
            module="tlsprobe",
            kind="tls.cert.expired",
            host="10.0.0.5",
            port=443,
            severity=Severity.HIGH,
            detail={"subject": "CN=old.example.com", "days_left": -12},
        ),
    ]
    r.stats = {"sent": 2, "answered": 2, "open": 1}
    r.finish(0.5)
    return r


class RenderHtmlTest(unittest.TestCase):
    def setUp(self):
        self.html = render_html(_sample_result())

    def test_valid_document_shell(self):
        self.assertTrue(self.html.lstrip().lower().startswith("<!doctype html>"))
        self.assertIn("vtknet — scan", self.html)

    def test_findings_present_with_severity(self):
        self.assertIn("port.open", self.html)
        self.assertIn("tls.cert.expired", self.html)
        self.assertIn("badge high", self.html)
        self.assertIn("badge info", self.html)

    def test_detail_is_html_escaped(self):
        self.assertNotIn("<script>alert(1)", self.html)
        self.assertIn("&lt;script&gt;", self.html)

    def test_evidence_truncated_and_escaped(self):
        self.assertIn("packet_hex", self.html)
        self.assertIn("4545", self.html)
        self.assertIn("…", self.html)  # long evidence shortened

    def test_stats_and_args_rendered(self):
        self.assertIn("duration", self.html)
        self.assertIn("scan_type", self.html)
        self.assertIn("10.0.0.5", self.html)

    def test_empty_result_shows_no_findings_row(self):
        empty = ScanResult(command="sweep")
        self.assertIn("no findings", render_html(empty))

    def test_write_html_to_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.html")
            write_html(_sample_result(), path)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("port.open", content)
            json.loads(json.dumps({"ok": True}))  # sanity: json still importable
            self.assertGreater(os.path.getsize(path), 500)


if __name__ == "__main__":
    unittest.main()
