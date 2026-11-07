import os
import tempfile
import unittest

from scapy.all import Dot11, RadioTap, Raw, wrpcap

from vtknet.modules.wifi import (
    analyze_frames,
    analyze_offline,
    beacon_frame,
    classify_frame,
    deauth_frame,
)

AP1, AP2, AP3 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:09"


def _sample_frames() -> list:
    return [
        beacon_frame("CorpNet", AP1, channel=6),
        beacon_frame("CorpNet", AP2, channel=11),  # evil twin of AP1
        beacon_frame("HomeNet", AP3, channel=1),
        *[deauth_frame(AP1, reason=3) for _ in range(3)],
    ]


class ClassifyTest(unittest.TestCase):
    def test_deauth_classified(self):
        info = classify_frame(deauth_frame(AP1, client_mac="aa:bb:cc:00:00:55"))
        self.assertEqual(info["type"], "deauth")
        self.assertEqual(info["from"], AP1)
        self.assertEqual(info["target"], "aa:bb:cc:00:00:55")
        self.assertEqual(info["reason"], 7)

    def test_beacon_classified(self):
        info = classify_frame(beacon_frame("LabNet", AP3, channel=9))
        self.assertEqual(info["type"], "beacon")
        self.assertEqual(info["ssid"], "LabNet")
        self.assertEqual(info["bssid"], AP3)
        self.assertEqual(info["channel"], 9)

    def test_other_frame_returns_none(self):
        data_frame = RadioTap() / Dot11(type=2, subtype=0, addr1=AP1, addr2=AP2, addr3=AP3) / Raw(b"x")
        self.assertIsNone(classify_frame(data_frame))


class AnalyzeTest(unittest.TestCase):
    def test_evil_twin_and_storm_detected(self):
        findings, stats = analyze_frames(_sample_frames())
        kinds = {f.kind for f in findings}
        self.assertIn("wifi.evil-twin", kinds)
        self.assertIn("wifi.deauth.storm", kinds)
        self.assertEqual(stats["deauth_frames"], 3)
        self.assertEqual(stats["distinct_ssids"], 2)

    def test_rogue_ap_with_known_bssid(self):
        findings, _ = analyze_frames(
            _sample_frames(), known_ssid="CorpNet", known_bssids=[AP1]
        )
        rogue = [f for f in findings if f.kind == "wifi.rogue-ap"]
        self.assertEqual(len(rogue), 1)
        self.assertEqual(rogue[0].detail["unknown_bssids"], [AP2])

    def test_below_threshold_no_storm(self):
        findings, _ = analyze_frames(_sample_frames(), deauth_threshold=10)
        self.assertNotIn("wifi.deauth.storm", {f.kind for f in findings})

    def test_severity_levels(self):
        findings, _ = analyze_frames(_sample_frames())
        sev = {f.kind: f.severity.value for f in findings}
        self.assertEqual(sev["wifi.deauth.storm"], "high")
        self.assertEqual(sev["wifi.evil-twin"], "medium")


class OfflineTest(unittest.TestCase):
    def test_analyze_offline_end_to_end(self):
        """Frames -> pcap -> real AsyncSniffer offline -> detector findings."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "wifi.pcap")
            wrpcap(path, _sample_frames())
            findings, stats = analyze_offline(path)
            kinds = {f.kind for f in findings}
            self.assertIn("wifi.evil-twin", kinds)
            self.assertIn("wifi.deauth.storm", kinds)
            self.assertEqual(stats["frames"], 6)


if __name__ == "__main__":
    unittest.main()
