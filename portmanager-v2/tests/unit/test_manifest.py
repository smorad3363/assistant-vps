"""Static non-interference and source integrity invariants."""
import hashlib
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent


class SourceTests(TestCase):
    def test_manifest_checksums(self):
        lines = (ROOT / "manifest.sha256").read_text().splitlines()
        self.assertGreater(len(lines), 5)
        for line in lines:
            expected, path = line.split("  ", 1)
            actual = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, path)

    def test_forbidden_v1_writes_are_absent(self):
        # Network engine will extend this policy with stronger AST checks.
        code = (ROOT / "pm2" / "cli.py").read_text()
        self.assertNotIn("iptables -F", code)
        self.assertNotIn("qdisc del", code)
        self.assertNotIn("shell=True", code)
        self.assertNotIn("iptables-restore", code)

    def test_no_old_v1_path_copied_as_v2(self):
        self.assertTrue((REPO / "portmanager-dashboard" / "install.sh").exists())
        self.assertTrue((REPO / "portmanager-v1" / "install.sh").exists())
        self.assertFalse((ROOT / "portmanager.sh.gz.b64").exists())
