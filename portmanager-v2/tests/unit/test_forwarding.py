"""Only V2-owned sysctl drop-in may be created/removed."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pm2 import forwarding
from pm2.errors import PM2Error


class ForwardingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patch = mock.patch.object(forwarding, "DROPIN", Path(tmp.name) / "91-pm2.conf")
        patch.start()
        self.addCleanup(patch.stop)

    def test_owned_dropin_keeps_live_kernel_value_on_remove(self):
        with (mock.patch.object(forwarding.os, "geteuid", return_value=0),
              mock.patch.object(forwarding.discovery, "forwarding_enabled", return_value=False),
              mock.patch.object(forwarding.discovery, "run", return_value="net.ipv4.ip_forward = 1")):
            changed = forwarding.activate()
            self.assertTrue(changed["changed"])
            self.assertEqual(forwarding.DROPIN.read_bytes(), forwarding.BODY)
            removed = forwarding.remove_dropin()
            self.assertTrue(removed["live_forwarding_left_unchanged"])
            self.assertFalse(forwarding.DROPIN.exists())

    def test_foreign_config_refused(self):
        forwarding.DROPIN.write_text("net.ipv4.ip_forward=0\n")
        with self.assertRaises(PM2Error) as err:
            forwarding.preflight()
        self.assertEqual(err.exception.code, "E_CONFLICT")
        self.assertEqual(forwarding.DROPIN.read_text(), "net.ipv4.ip_forward=0\n")
