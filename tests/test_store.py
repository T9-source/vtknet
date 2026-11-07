import os
import tempfile
import unittest

from vtknet.core.models import Evidence, Finding, ScanResult, Severity
from vtknet.core.store import DEFAULT_DB, VOLATILE_DETAIL_KEYS, History, finding_uid


def _scan_result(port, ttl=64, kind="port.open", host="10.0.0.5"):
    r = ScanResult(command="scan", args={"target": host})
    r.findings = [
        Finding(
            module="scanner",
            kind=kind,
            host=host,
            port=port,
            state="open",
            severity=Severity.INFO,
            detail={"ttl": ttl, "flags": "SA"},
            evidence=[Evidence("packet_hex", "45" * 8, "syn/ack")],
        )
    ]
    r.finish(0.5)
    return r


def _summary_result(started):
    r = ScanResult(command="pcap", args={"pcap_file": "t.pcap"})
    r.findings = [
        Finding(
            module="inspect",
            kind="pcap.summary",
            host="t.pcap",
            detail={"packets": 5, "started": started, "duration_s": 1.5},
        )
    ]
    r.finish(0.1)
    return r


class StoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self._tmp.name, "history.db")
        self.h = History(self.db)

    def tearDown(self):
        self.h.close()
        self._tmp.cleanup()

    def test_save_and_get_roundtrip(self):
        run_id = self.h.save_result(_scan_result(443))
        run = self.h.get_run(run_id)
        self.assertEqual(run["command"], "scan")
        self.assertEqual(len(run["findings"]), 1)
        f = run["findings"][0]
        self.assertEqual(f["port"], 443)
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["detail"]["flags"], "SA")
        self.assertEqual(f["evidence"][0]["kind"], "packet_hex")
        self.assertEqual(f["uid"], "scanner|port.open|10.0.0.5|443")

    def test_list_runs(self):
        self.h.save_result(_scan_result(443))
        self.h.save_result(_scan_result(8080))
        runs = self.h.list_runs()
        self.assertEqual([r["id"] for r in runs], [2, 1])  # newest first
        self.assertEqual(runs[0]["findings"], 1)

    def test_get_unknown_run(self):
        self.assertIsNone(self.h.get_run(999))

    def test_diff_added_removed_changed(self):
        a = self.h.save_result(_scan_result(443))  # port 443 open
        b = self.h.save_result(_scan_result(8080, ttl=32))  # 443 gone, 8080 open
        d = self.h.diff(a, b)
        self.assertEqual([f["port"] for f in d["added"]], [8080])
        self.assertEqual([f["port"] for f in d["removed"]], [443])
        self.assertEqual(d["changed"], [])

    def test_diff_same_scan_is_clean(self):
        a = self.h.save_result(_scan_result(443, ttl=64))
        b = self.h.save_result(_scan_result(443, ttl=64))
        d = self.h.diff(a, b)
        self.assertEqual(d["added"], [])
        self.assertEqual(d["removed"], [])
        self.assertEqual(d["changed"], [])

    def test_diff_detects_detail_change(self):
        a = self.h.save_result(_scan_result(443, ttl=64))
        b = self.h.save_result(_scan_result(443, ttl=32))  # same port, different TTL
        d = self.h.diff(a, b)
        self.assertEqual(len(d["changed"]), 1)
        self.assertEqual(d["changed"][0]["before"]["ttl"], 64)
        self.assertEqual(d["changed"][0]["after"]["ttl"], 32)

    def test_volatile_keys_ignored_in_diff(self):
        r1 = self.h.save_result(_summary_result("2026-01-01T00:00:00.000+00:00"))
        r2 = self.h.save_result(_summary_result("2026-06-06T00:00:00.000+00:00"))
        d = self.h.diff(r1, r2)
        self.assertEqual(d["changed"], [])  # only started/duration differ
        self.assertIn("started", VOLATILE_DETAIL_KEYS)

    def test_diff_unknown_run_raises_valueerror(self):
        with self.assertRaises(ValueError):
            self.h.diff(1, 42)

    def test_finding_uid_shape(self):
        f = Finding(module="scanner", kind="port.open", host="h", port=None)
        self.assertEqual(finding_uid(f), "scanner|port.open|h|")

    def test_default_db_path_shape(self):
        self.assertTrue(DEFAULT_DB.endswith("history.db"))
        self.assertIn(".vtknet", DEFAULT_DB)


if __name__ == "__main__":
    unittest.main()
