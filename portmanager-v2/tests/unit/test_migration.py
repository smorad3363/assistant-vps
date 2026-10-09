"""Immutable V1 archive, cron isolation, owned V2 alias, and rollback tests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from pm2 import migration, shaping
from pm2.errors import PM2Error

V1 = b"#!/usr/bin/env bash\n# PORTMANAGER_ACCT original\necho legacy\n"
CRON = ("SHELL=/bin/bash\n"
        "*/1 * * * * /usr/local/bin/portmanager sample >/dev/null 2>&1\n"
        "@reboot sleep 30 && /usr/local/bin/portmanager apply >/dev/null 2>&1\n"
        "0 4 * * * /usr/bin/backup\n")


class MigrateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.bin = base / "portmanager"
        self.v2 = base / "portmanager2"
        self.v2.write_text("#!/bin/sh\nexit 0\n")
        self.archive = base / "archived"
        self.cron = CRON
        patches = [
            mock.patch.object(migration, "BIN", self.bin),
            mock.patch.object(migration, "V2_TARGET", str(self.v2)),
            mock.patch.object(migration, "ARCHIVE", self.archive),
            mock.patch.object(migration, "MARKER", self.archive / "archive.json"),
            mock.patch.object(migration, "FROZEN", self.archive / "portmanager.v1"),
            mock.patch.object(migration.os, "geteuid", return_value=0),
            mock.patch.object(migration.shutil, "which", return_value="/usr/bin/crontab"),
            mock.patch.object(migration, "_read_cron", side_effect=lambda: self.cron),
            mock.patch.object(migration, "_write_cron", side_effect=self.change_cron),
            mock.patch.object(migration.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, "", ""))
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def change_cron(self, value):
        self.cron = value

    def test_archive_original_v1_cron_then_public_launcher_is_v2(self):
        self.bin.write_bytes(V1)
        result = migration.activate()
        self.assertTrue(result["legacy_archived"])
        self.assertEqual(result["active"], "v2")
        self.assertTrue(self.bin.is_symlink())
        self.assertEqual(os.readlink(self.bin), str(self.v2))
        self.assertEqual(migration.FROZEN.read_bytes(), V1)
        marker = json.loads(migration.MARKER.read_text())
        self.assertEqual(marker["sha256"], hashlib.sha256(V1).hexdigest())
        self.assertEqual(len(marker["disabled_cron"]), 2)
        self.assertEqual(self.cron, "SHELL=/bin/bash\n0 4 * * * /usr/bin/backup\n")
        self.assertEqual(migration.activate()["changed"], False)

    def test_fresh_install_v2_public_alias_no_legacy_archive(self):
        x = migration.activate()
        self.assertTrue(x["changed"])
        self.assertFalse(migration.MARKER.exists())
        self.assertEqual(os.readlink(self.bin), str(self.v2))

    def test_foreign_binary_is_never_overwritten(self):
        self.bin.write_text("#!/bin/sh\necho unrelated\n")
        with self.assertRaises(PM2Error) as err:
            migration.activate()
        self.assertEqual(err.exception.code, "E_CONFLICT")
        self.assertFalse(self.bin.is_symlink())
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.cron, CRON)

    def test_foreign_symlink_is_never_replaced(self):
        other = self.bin.parent / "foreign"
        other.write_text("elsewhere")
        self.bin.symlink_to(other)
        with self.assertRaises(PM2Error):
            migration.activate()
        self.assertEqual(os.readlink(self.bin), str(other))

    def test_unknown_cron_commands_fail_closed(self):
        self.bin.write_bytes(V1)
        self.cron += "* * * * * /usr/local/bin/portmanager arbitrary\n"
        with self.assertRaises(PM2Error):
            migration.activate()
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.bin.is_symlink())

    def test_cron_failure_restores_v1(self):
        self.bin.write_bytes(V1)
        with mock.patch.object(migration, "_write_cron",
                               side_effect=PM2Error("E_APPLY", "cron failure")):
            with self.assertRaises(PM2Error):
                migration.activate()
        self.assertEqual(self.bin.read_bytes(), V1)
        self.assertFalse(self.bin.is_symlink())
        self.assertEqual(self.cron, CRON)

    def test_owned_archive_checksum_detects_corruption(self):
        self.bin.write_bytes(V1)
        migration.activate()
        migration.FROZEN.write_text("tampered")
        with self.assertRaises(PM2Error):
            migration.preflight()

    def test_shaping_knows_v2_public_symlink_is_not_v1(self):
        self.bin.symlink_to(self.v2)
        with (mock.patch.object(shaping, "_V1", self.bin),
              mock.patch.object(shaping, "_MAIN_V2", str(self.v2)),
              mock.patch.object(shaping, "_LEGACY_ARCHIVE", self.archive / "archive.json")):
            self.assertFalse(shaping.legacy_conflict())
            self.bin.unlink()
            self.bin.write_bytes(V1)
            self.assertTrue(shaping.legacy_conflict())


if __name__ == "__main__":
    unittest.main()
