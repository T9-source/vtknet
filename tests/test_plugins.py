import tempfile
import unittest
from pathlib import Path

from vtknet.core.plugins import VtkPlugin, discover, load_file_plugins


class _Broken(VtkPlugin):
    name = "broken"
    help = "instantiation intentionally fails"

    def __init__(self):
        raise RuntimeError("nope")


GOOD_PLUGIN = '''
from vtknet.plugins import VtkPlugin

class HelloPorts(VtkPlugin):
    name = "hello-ports"
    help = "test plugin: SYN probe of a fixed port list"
    def add_arguments(self, parser):
        parser.add_argument("target")
    def run(self, engine, args):
        return [], {"sent": 3}
'''

SECOND_PLUGIN = '''
from vtknet.plugins import VtkPlugin

class Ping(VtkPlugin):
    name = "ping"
    help = "second test plugin"
    def run(self, engine, args):
        return [], {}
'''


class DiscoveryTest(unittest.TestCase):
    def test_load_file_plugins_from_dir(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "hello_ports.py").write_text(GOOD_PLUGIN)
            Path(d, "ping.py").write_text(SECOND_PLUGIN)
            Path(d, "not_python.txt").write_text("ignored")
            found = load_file_plugins(d)
            names = {p.name for p in found}
            self.assertEqual(names, {"hello-ports", "ping"})

    def test_broken_plugin_file_does_not_kill_loader(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "bad.py").write_text("raise RuntimeError('boom')\n")
            Path(d, "good.py").write_text(GOOD_PLUGIN)
            names = {p.name for p in load_file_plugins(d)}
            self.assertEqual(names, {"hello-ports"})

    def test_plugin_without_name_is_dropped_at_discovery(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "no_name.py").write_text("from vtknet.plugins import VtkPlugin\nclass A(VtkPlugin): pass\n")
            self.assertEqual(len(load_file_plugins(d)), 1)  # raw loader returns it…
            self.assertEqual(discover([d]), [])  # …discover() filters it out

    def test_missing_dir_is_empty_not_fatal(self):
        self.assertEqual(load_file_plugins("/nonexistent-dir-xyz"), [])

    def test_discover_dedupes_by_name(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "hello_ports.py").write_text(GOOD_PLUGIN)
            found = discover([d, d])  # same dir twice
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].name, "hello-ports")


if __name__ == "__main__":
    unittest.main()
