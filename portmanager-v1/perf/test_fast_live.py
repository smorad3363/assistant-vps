"""Pure parser tests; no iptables privileges or network mutation needed."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock
import subprocess

FILE = Path(__file__).with_name("fast_live.py")
spec = importlib.util.spec_from_file_location("v1_fast_live", FILE)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class V1FastLiveTests(unittest.TestCase):
    def test_parse_prefixed_bytes_ipv4_ipv6(self):
        sample = """*mangle
[4:200] -A PORTMANAGER_ACCT -p tcp -m comment --comment pm-ul:443
[5:2000] -A PORTMANAGER_ACCT -p udp -m comment --comment pm-dl:443
[1:250] -A PORTMANAGER_ACCT -p tcp --comment "pm-ul:2053"
[7:999] -A FOREIGN -m comment --comment pm-dl:443
COMMIT
"""
        data, count = app.parse_rules(sample)
        self.assertEqual(count, 3)
        self.assertEqual(data[443], [2000, 200])
        self.assertEqual(data[2053], [0, 250])

    def test_parse_suffix_counters(self):
        data, count = app.parse_rules(
            '-A PORTMANAGER_ACCT -m comment --comment "pm-ul:53" -c 2 800\n')
        self.assertEqual(count, 1)
        self.assertEqual(data[53], [0, 800])

    def test_requires_known_counters(self):
        with self.assertRaises(ValueError):
            app.parse_rules('-A PORTMANAGER_ACCT --comment pm-ul:53')

    def test_negative_counter_reset_is_not_a_negative_rate(self):
        previous = {443: [10000, 10000]}
        current = {443: [200, 300]}
        self.assertEqual(app.delta(previous, current, 2), [(443, 0.0, 0.0)])

    def test_default_interval_enforces_minimum(self):
        with self.assertRaises(SystemExit):
            app.main(["--interval", "1", "--once"])

    def test_snapshot_only_uses_read_only_iptables_save(self):
        sample = '[2:350] -A PORTMANAGER_ACCT -p tcp --comment pm-ul:443\n'
        with mock.patch.object(app.shutil, "which", return_value="/usr/bin/iptables-save"):
            with mock.patch.object(app.subprocess, "run",
                                   return_value=subprocess.CompletedProcess(
                                       args=[], returncode=0, stdout=sample, stderr="")
                                   ) as execute:
                values, count, seconds = app.snapshot(["iptables-save"])
        self.assertEqual(values[443], [0, 350])
        self.assertEqual(count, 1)
        self.assertEqual(execute.call_args.args[0],
                         ["iptables-save", "-c", "-t", "mangle"])


if __name__ == "__main__":
    unittest.main()
