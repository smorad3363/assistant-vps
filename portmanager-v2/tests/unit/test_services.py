"""Phase-1 systemd unit lifecycle never touches V1 or service activation."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

from pm2 import services
from pm2.errors import PM2Error


def fake_systemctl(args):
    if args == ["daemon-reload"]:
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    if args[0] == "is-enabled":
        return SimpleNamespace(returncode=1, stdout="disabled\n", stderr="")
    if args[0] == "is-active":
        return SimpleNamespace(returncode=3, stdout="inactive\n", stderr="")
    raise AssertionError(f"Unexpected systemctl invocation: {args}")


class ServicesTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.systemd = base / "systemd"
        self.etc = base / "portmanager2"
        self.systemd.mkdir()
        self.etc.mkdir()
        self.v1_file = base / "V1_DO_NOT_TOUCH"
        self.v1_file.write_text("frozen V1\n")
        patches = [
            mock.patch.object(services, "SYSTEMD", self.systemd),
            mock.patch.object(services, "MARKER", self.etc / "systemd-owner.json"),
            mock.patch.object(services, "_check_root", return_value=None),
            mock.patch.object(services, "_run", side_effect=fake_systemctl),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_install_idempotent_and_remove(self):
        first = services.install()
        self.assertTrue(first["changed"])
        self.assertFalse(first["enabled"])
        marker = json.loads(services.MARKER.read_text())
        self.assertEqual(set(marker["units"]), set(services.UNIT_NAMES))
        original = {n: (self.systemd / n).read_bytes() for n in services.UNIT_NAMES}
        again = services.install()
        self.assertFalse(again["changed"])
        self.assertEqual(original, {n: (self.systemd / n).read_bytes()
                                    for n in services.UNIT_NAMES})
        self.assertEqual(services.remove()["enabled"], False)
        self.assertFalse(services.MARKER.exists())
        self.assertTrue(all(not (self.systemd / n).exists() for n in services.UNIT_NAMES))
        self.assertEqual(self.v1_file.read_text(), "frozen V1\n")

    def test_unowned_foreign_unit_fails_closed(self):
        path = self.systemd / services.UNIT_NAMES[0]
        path.write_text("foreign service\n")
        with self.assertRaises(PM2Error) as error:
            services.install()
        self.assertEqual(error.exception.code, "E_CONFLICT")
        self.assertEqual(path.read_text(), "foreign service\n")

    def test_modified_owned_unit_blocks_uninstall(self):
        services.install()
        path = self.systemd / services.UNIT_NAMES[1]
        path.write_text("external modifications")
        with self.assertRaises(PM2Error) as error:
            services.remove()
        self.assertEqual(error.exception.code, "E_CONFLICT")
        self.assertTrue(path.exists())

    def test_symlinked_unit_rejected(self):
        foreign = self.v1_file
        (self.systemd / services.UNIT_NAMES[0]).symlink_to(foreign)
        with self.assertRaises(PM2Error) as error:
            services.install()
        self.assertEqual(error.exception.code, "E_CONFLICT")
        self.assertEqual(foreign.read_text(), "frozen V1\n")

    def test_active_units_block_remove(self):
        services.install()
        def active(args):
            if args[0] == "is-active":
                return SimpleNamespace(returncode=0, stdout="active\n", stderr="")
            return fake_systemctl(args)
        with mock.patch.object(services, "_run", side_effect=active):
            with self.assertRaises(PM2Error) as error:
                services.remove()
        self.assertEqual(error.exception.code, "E_CONFLICT")

    def test_masked_unit_blocks_deletion(self):
        services.install()
        def masked(args):
            if args[0] == "is-enabled":
                return SimpleNamespace(returncode=1, stdout="masked\\n", stderr="")
            return fake_systemctl(args)
        with mock.patch.object(services, "_run", side_effect=masked):
            with self.assertRaises(PM2Error) as error:
                services.remove()
        self.assertEqual(error.exception.code, "E_CONFLICT")
        self.assertTrue(services.MARKER.is_file())

    def test_daemon_reload_failure_restores_units_and_marker(self):
        def failed(args):
            if args == ["daemon-reload"]:
                # First reload fails; rollback reload succeeds.
                if not hasattr(failed, "already_failed"):
                    failed.already_failed = True
                    return SimpleNamespace(returncode=1, stderr="fail", stdout="")
            return fake_systemctl(args)
        with mock.patch.object(services, "_run", side_effect=failed):
            with self.assertRaises(PM2Error) as error:
                services.install()
        self.assertEqual(error.exception.code, "E_APPLY")
        self.assertFalse(services.MARKER.exists())
        self.assertTrue(all(not (self.systemd / n).exists() for n in services.UNIT_NAMES))
