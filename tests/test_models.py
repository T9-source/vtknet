import json
import unittest

from vtknet.core.models import Evidence, Finding, PortState, ScanResult, Severity


class FindingTest(unittest.TestCase):
    def test_to_dict_serializes_enums_and_evidence(self):
        f = Finding(
            module="scanner",
            kind="port.open",
            host="10.0.0.5",
            port=443,
            state=PortState.OPEN.value,
            detail={"scan": "syn", "flags": "SA"},
            evidence=[Evidence("packet_hex", "deadbeef", "syn/ack")],
            severity=Severity.INFO,
        )
        d = f.to_dict()
        self.assertEqual(d["severity"], "info")
        self.assertEqual(d["port"], 443)
        self.assertEqual(d["detail"]["flags"], "SA")
        self.assertEqual(d["evidence"][0]["data"], "deadbeef")
        self.assertEqual(len(d["id"]), 12)
        json.dumps(d)  # must be JSON-clean

    def test_defaults_are_generated(self):
        f1, f2 = Finding(module="m", kind="k", host="h"), Finding(module="m", kind="k", host="h")
        self.assertNotEqual(f1.id, f2.id)
        self.assertTrue(f1.timestamp)


class ScanResultTest(unittest.TestCase):
    def test_to_json_roundtrip(self):
        r = ScanResult(command="scan", args={"target": "10.0.0.5"})
        r.stats = {"sent": 3, "answered": 1}
        r.finish(1.234)
        parsed = json.loads(r.to_json())
        self.assertEqual(parsed["command"], "scan")
        self.assertEqual(parsed["stats"]["sent"], 3)
        self.assertEqual(parsed["duration_s"], 1.234)
        self.assertTrue(parsed["finished"])
        self.assertEqual(parsed["findings"], [])


if __name__ == "__main__":
    unittest.main()
