import contextlib
import io
import json
import os
import tempfile
import unittest

from vtknet.cli import EXIT_OK, EXIT_USAGE, build_parser, main


class ParserTest(unittest.TestCase):
    def test_scan_defaults(self):
        args = build_parser().parse_args(["scan", "10.0.0.5"])
        self.assertEqual(args.scan_type, "syn")
        self.assertEqual(args.ports, "1-1024")
        self.assertEqual(args.rate, 100.0)

    def test_subcommand_required(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args([])

    def test_invalid_scan_type_rejected(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["scan", "10.0.0.5", "--type", "bogus"])


class MainTest(unittest.TestCase):
    def test_dry_run_json_emits_valid_report(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["scan", "127.0.0.1", "--ports", "80,443", "--dry-run", "--json"])
        self.assertEqual(code, EXIT_OK)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(parsed["command"], "scan")
        self.assertEqual(parsed["stats"]["sent"], 2)
        self.assertEqual(parsed["findings"], [])
        self.assertTrue(parsed["finished"])

    def test_dry_run_human_summary(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["sweep", "127.0.0.1", "--dry-run"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("== vtk sweep ==", buf.getvalue())

    def test_cidr_into_single_host_scan_is_usage_error(self):
        self.assertEqual(main(["scan", "10.0.0.0/24", "--dry-run"]), EXIT_USAGE)

    def test_bad_port_spec_is_usage_error(self):
        self.assertEqual(main(["scan", "127.0.0.1", "--ports", "99999", "--dry-run"]), EXIT_USAGE)


class Phase3Test(unittest.TestCase):
    def test_fuzz_dry_run(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["fuzz", "203.0.113.9", "--count", "5", "--base", "tcp", "--dry-run"])
        self.assertEqual(code, EXIT_OK)

    def test_wifi_dry_run(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["wifi", "--dry-run"])
        self.assertEqual(code, EXIT_OK)

    def test_wifi_offline_end_to_end(self):
        from scapy.all import wrpcap

        from vtknet.modules.wifi import beacon_frame, deauth_frame

        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "wifi.pcap")
            frames = [
                beacon_frame("CorpNet", "aa:bb:cc:00:00:01"),
                beacon_frame("CorpNet", "aa:bb:cc:00:00:02"),
                *[deauth_frame("aa:bb:cc:00:00:01") for _ in range(3)],
            ]
            wrpcap(pcap, frames)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["wifi", "--offline", pcap, "--json"])
            self.assertEqual(code, EXIT_OK)
            out = buf.getvalue()
            self.assertIn("wifi.evil-twin", out)
            self.assertIn("wifi.deauth.storm", out)

    def test_mitm_dry_run(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(
                ["mitm", "--victim", "192.0.2.10", "--gateway", "192.0.2.1", "--dry-run"]
            )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("mitm.planned", buf.getvalue())

    def test_mitm_requires_victim_and_gateway(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["mitm"])


class Phase4Test(unittest.TestCase):
    def test_quic_dry_run(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["quic", "203.0.113.9", "--dry-run"])
        self.assertEqual(code, EXIT_OK)

    def test_plugins_list(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["plugins"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("plugins", buf.getvalue())  # stats line prints the count context

    def test_plugin_loaded_from_dir_and_runnable_dry_run(self):
        plugin_src = (
            "from vtknet.plugins import VtkPlugin\n"
            "class Greet(VtkPlugin):\n"
            "    name = 'greet'\n"
            "    help = 'test plugin'\n"
            "    def add_arguments(self, parser):\n"
            "        parser.add_argument('target')\n"
            "    def run(self, engine, args):\n"
            "        return [], {'sent': 1}\n"
        )
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "greet.py"), "w") as fh:
                fh.write(plugin_src)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["--plugin-dir", d, "greet", "127.0.0.1", "--dry-run"])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("== vtk greet ==", buf.getvalue())

    def test_plugin_cannot_shadow_builtin(self):
        plugin_src = (
            "from vtknet.plugins import VtkPlugin\n"
            "class Evil(VtkPlugin):\n"
            "    name = 'scan'\n"
            "    help = 'tries to shadow a builtin'\n"
            "    def run(self, engine, args):\n"
            "        return [], {}\n"
        )
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "evil.py"), "w") as fh:
                fh.write(plugin_src)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["--plugin-dir", d, "plugins", "--json"])
            self.assertEqual(code, EXIT_OK)
            lines = buf.getvalue().strip().splitlines()
            self.assertIn("no plugins found", lines[0])  # shadowed plugin is skipped
            start = lines.index("{")  # pretty-printed JSON report follows
            parsed = json.loads("\n".join(lines[start:]))
            self.assertEqual(parsed["stats"]["plugins"], 0)

    def test_html_report_written(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.html")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(
                    ["scan", "127.0.0.1", "--ports", "80", "--dry-run", "--html", path]
                )
            self.assertEqual(code, EXIT_OK)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("<!doctype html>", content)
            self.assertIn("vtknet — scan", content)


class Phase5Test(unittest.TestCase):
    def test_inspect_hex_json(self):
        from scapy.all import IP, TCP

        evidence = bytes(IP(dst="203.0.113.9") / TCP(dport=443, flags="S")).hex()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["inspect", "--hex", evidence, "--json"])
        self.assertEqual(code, EXIT_OK)
        parsed = json.loads(buf.getvalue())
        layers = parsed["findings"][0]["detail"]["layers"]
        self.assertEqual(layers, ["IP", "TCP"])  # IP fallback decoding

    def test_inspect_requires_one_source(self):
        self.assertEqual(main(["inspect"]), EXIT_USAGE)
        self.assertEqual(main(["inspect", "--hex", "aa", "--file", "x"]), EXIT_USAGE)

    def test_pcap_stats_end_to_end(self):
        from vtknet.modules.synthetic import write_trace

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trace.pcap")
            write_trace("tcp_scan", path, seed=5, count=9)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["pcap", path, "--json"])
            self.assertEqual(code, EXIT_OK)
            lines = buf.getvalue().strip().splitlines()
            parsed = json.loads("\n".join(lines[lines.index("{"):]))
            self.assertEqual(parsed["stats"]["packets"], 9)

    def test_synth_replay_dry_run(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "flood.pcap")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(
                    ["synth", "--scenario", "syn_flood", "--pcap", path,
                     "--count", "5", "--replay", "lo", "--dry-run"]
                )
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
