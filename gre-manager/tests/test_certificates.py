import json
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from panel import certificates
from panel.store import Paths, Store


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Paths(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_configure_public_ip_preserves_manual_choice(self):
        response = subprocess.CompletedProcess([], 0, '[{"prefsrc":"65.109.211.168"}]', '')
        with patch.object(certificates, "command", return_value=response):
            saved = certificates.configure(self.store)
        self.assertEqual(saved["address"], "65.109.211.168")
        saved.update(enabled=False, status="manual")
        certificates.save(self.store.paths, saved)
        with patch.object(certificates, "command") as command:
            self.assertFalse(certificates.configure(self.store)["enabled"])
            command.assert_not_called()

    def test_validation_failure_cleans_interception_and_retains_certificate(self):
        paths = self.store.paths
        (paths.tls / "cert.pem").write_text("last-good-certificate")
        certificates.save(paths, {"enabled": True, "address": "65.109.211.168"})
        def command(*args, **kwargs):
            if args[0] == "ip":
                return subprocess.CompletedProcess(args, 0, '[{"addr_info":[{"local":"65.109.211.168"}]}]', '')
            raise RuntimeError("ACME validation failed")
        probe = MagicMock()
        probe.__enter__.return_value.getsockname.return_value = ("0.0.0.0", 18990)
        with patch.object(certificates, "command", side_effect=command), patch.object(certificates, "firewall") as firewall, patch.object(certificates.socket, "socket", return_value=probe):
            with self.assertRaisesRegex(RuntimeError, "validation failed"):
                certificates.renew(self.store)
            self.assertEqual(firewall.call_args_list[0].args, ("65.109.211.168", 18990))
            self.assertEqual(firewall.call_args_list[-1].args, ())
        self.assertEqual((paths.tls / "cert.pem").read_text(), "last-good-certificate")
        self.assertEqual(certificates.status(paths)["status"], "error")

    def test_disabled_and_not_due_do_not_interrupt_port_80(self):
        paths = self.store.paths
        certificates.save(paths, {"enabled": False})
        with patch.object(certificates, "command") as command:
            certificates.renew(self.store)
            command.assert_not_called()
        for name in ("cert.pem", "key.pem"):
            (paths.tls / name).write_text("fixture")
        certificates.save(paths, {"enabled": True, "status": "ready", "expires_at": 20000000000})
        with patch.object(certificates, "command") as command:
            certificates.renew(self.store)
            command.assert_not_called()

    def test_changed_address_does_not_install_interception(self):
        certificates.save(self.store.paths, {"enabled": True, "address": "65.109.211.168"})
        with patch.object(certificates, "command", return_value=subprocess.CompletedProcess([], 0, '[]', '')), patch.object(certificates, "firewall") as firewall:
            with self.assertRaisesRegex(ValueError, "no longer assigned"):
                certificates.renew(self.store)
            firewall.assert_not_called()
        self.assertEqual(certificates.status(self.store.paths)["status"], "error")

    def test_service_timeout_cleanup_reports_retry_instead_of_stuck_renewing(self):
        certificates.save(self.store.paths, {"enabled": True, "status": "renewing"})
        with patch.object(certificates, "firewall") as firewall, patch.object(certificates, "Store", return_value=self.store), patch("sys.argv", ["certificates", "cleanup"]), patch.dict("os.environ", {"SERVICE_RESULT": "timeout"}):
            certificates.main()
            firewall.assert_called_once_with()
        self.assertEqual(certificates.status(self.store.paths)["status"], "error")
