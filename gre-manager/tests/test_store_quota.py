"""File quotas protect recent samples, durable counters and recovery archives."""
from contextlib import closing
import fcntl
import json
import socket
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from panel.demo import DemoController, DemoEngine, DemoRemote
from panel.store import MIB, MIN_FREE_BYTES, Paths, Store, TRAFFIC_SCHEMA, prune_install_backups


class StorageQuotaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.paths = Paths(temporary.name)

    def controller(self, store):
        controller = DemoController(store, DemoEngine(), DemoRemote(self.paths))
        self.addCleanup(controller.executor.shutdown)
        self.addCleanup(controller.v2_executor.shutdown)
        controller.last_prune = controller.last_backup = time.time()
        return controller

    def test_legacy_file_shrinks_under_volume_pressure(self):
        now = int(time.time() // 60) * 60
        identity = "abcde12345"
        with closing(sqlite3.connect(self.paths.db)) as db, db:
            db.executescript(TRAFFIC_SCHEMA)
            db.executemany("INSERT INTO samples VALUES(?,?,?,?,?)",
                           ((now - (230000 - n) * 60, identity, str(n % 128), n, n + 1) for n in range(230000)))
            db.execute("INSERT INTO samples VALUES(?,?,?,?,?)", (now, identity, "all", 7, 9))
            db.execute("INSERT INTO totals VALUES(?,?,?,?)", (identity, "all", 150, 350))
        store = Store(self.paths)
        store.set_password("preserve-this-password")
        settings = dict(store.config()["settings"], telemetry_limit_mib=16)
        self.assertGreater(store.telemetry_bytes(), 16 * MIB)
        with patch("panel.store.shutil.disk_usage", return_value=SimpleNamespace(free=MIN_FREE_BYTES + 256 * MIB)):
            for _ in range(24):
                store.prune(settings)
                if store.telemetry_bytes() <= 16 * MIB:
                    break
        self.assertLessEqual(store.telemetry_bytes(), 16 * MIB)
        with store.database() as db:
            self.assertEqual(db.execute("PRAGMA auto_vacuum").fetchone()[0], 2)
            self.assertEqual(tuple(db.execute("SELECT up,down FROM samples WHERE at=?", (now,)).fetchone()), (7, 9))
            self.assertEqual(tuple(db.execute("SELECT up,down FROM totals").fetchone()), (150, 350))
        store.login("admin", "preserve-this-password", "fixture")

    def test_low_disk_pauses_history_and_preserves_counter_deltas(self):
        store = Store(self.paths)
        identity = ("abcde12345", "all")
        with patch("panel.store.shutil.disk_usage", return_value=SimpleNamespace(free=MIN_FREE_BYTES - 1)):
            store.sample({identity: (100, 200)}, "epoch", now=120)
        with patch("panel.store.shutil.disk_usage", return_value=SimpleNamespace(free=MIN_FREE_BYTES + MIB)):
            store.sample({identity: (150, 250)}, "epoch", now=180)
        with store.database() as db:
            self.assertEqual([tuple(row) for row in db.execute("SELECT at,up,down FROM samples")], [(180, 50, 50)])
            self.assertEqual(tuple(db.execute("SELECT up,down FROM totals").fetchone()), (150, 250))

    def test_archive_fits_limit_and_keeps_recent_history_and_totals(self):
        store = Store(self.paths)
        identity = "abcde12345"
        with store.database() as db:
            db.executemany("INSERT INTO samples VALUES(?,?,?,?,?)",
                           ((i, identity, "all", i, i + 1) for i in range(45000)))
            db.execute("INSERT INTO totals VALUES(?,?,?,?)", (identity, "all", 43, 56))
        with patch("panel.store.shutil.disk_usage", return_value=SimpleNamespace(free=MIN_FREE_BYTES + MIB)):
            archive = store.backup(MIB)
        self.assertLessEqual(len(archive), MIB)
        _, telemetry = store.read_backup(archive)
        snapshot = self.paths.run / "snapshot.sqlite3"
        snapshot.write_bytes(telemetry)
        with closing(sqlite3.connect(snapshot)) as db:
            count, oldest, newest = db.execute("SELECT count(*),min(at),max(at) FROM samples").fetchone()
            self.assertGreater(count, 0)
            self.assertGreater(oldest, 0)
            self.assertEqual(newest, 44999)
            self.assertEqual(db.execute("SELECT up,down FROM totals").fetchone(), (43, 56))
        with store.database() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM samples").fetchone()[0], 45000)

    def test_rotation_accounts_for_bytes_and_preserves_last_on_write_failure(self):
        store = Store(self.paths)
        settings = dict(store.config()["settings"], backup_limit_mib=1)
        unrelated = self.paths.backups / "backup-manual.zip"
        unrelated.write_bytes(b"manual")
        with patch.object(store, "backup", return_value=b"b" * (600 * 1024)):
            for index in range(2):
                with patch("panel.store.time.strftime", return_value=f"backup-20261120-10000{index}"):
                    store.automatic_backup(settings)
            latest, = store.backup_files()
            self.assertEqual(latest.name, "backup-20261120-100001.zip")
            with patch("panel.store.atomic_write", side_effect=OSError("no space")):
                with self.assertRaises(OSError):
                    store.automatic_backup(settings)
        self.assertEqual(latest.stat().st_size, 600 * 1024)
        self.assertEqual(unrelated.read_bytes(), b"manual")

    def test_install_snapshot_rotation_preserves_current_and_manual_copies(self):
        root = self.paths.etc / "backups"
        root.mkdir()
        manual = root / "manual"
        manual.mkdir()
        snapshots = [root / f"install-20261120-10000{i}-{i}" for i in range(4)]
        for entry in snapshots:
            entry.mkdir()
            (entry / "panel.json").write_bytes(b"#" * MIB)
        with patch("panel.store.MAX_BACKUP_BYTES", 2 * MIB):
            prune_install_backups(snapshots[-1])
        self.assertEqual(set(root.iterdir()), {manual, *snapshots[-2:]})

    def test_failed_quota_change_keeps_every_preexisting_archive(self):
        store = Store(self.paths)
        controller = self.controller(store)
        for index in range(4):
            with patch("panel.store.time.strftime", return_value=f"backup-20261120-10000{index}"):
                store.automatic_backup()
        archives = {path.name: path.read_bytes() for path in store.backup_files()}
        proposed = store.config()
        proposed["settings"]["backup_keep"] = 1
        with patch.object(controller.engine, "apply", side_effect=[RuntimeError("fixture apply failure"), None]):
            with self.assertRaisesRegex(RuntimeError, "fixture apply failure"):
                controller.transaction(proposed)
        controller.maintain_storage(store.config()["settings"], time.time())
        self.assertEqual(store.config()["settings"]["backup_keep"], 7)
        self.assertEqual({path.name: path.read_bytes() for path in store.backup_files()}, archives)
        self.assertFalse(store.paths.staged_backup.exists())
        controller.transaction(proposed)
        confirmation = store.paths.etc / "web-pending.json"
        confirmation.touch()
        controller.maintain_storage(store.config()["settings"], time.time())
        self.assertEqual(len(store.backup_files()), 4)
        confirmation.unlink()
        controller.maintain_storage(store.config()["settings"], time.time())
        latest, = store.backup_files()
        stored_settings, _ = store.read_backup(latest.read_bytes())
        self.assertEqual(stored_settings["settings"]["backup_keep"], 7)

    def test_installer_lock_defers_destructive_maintenance(self):
        store = Store(self.paths)
        controller = self.controller(store)
        controller.last_prune = controller.last_backup = 0
        settings = store.config()["settings"]
        with patch.object(store, "prune") as prune, patch.object(store, "automatic_backup") as backup:
            with self.paths.install_lock.open("a") as installer:
                fcntl.flock(installer, fcntl.LOCK_EX)
                controller.maintain_storage(settings, time.time())
                prune.assert_not_called()
                backup.assert_not_called()
            controller.maintain_storage(settings, time.time())
            prune.assert_called_once_with(settings)
            backup.assert_called_once()

    def test_manual_backup_during_unconfirmed_port_uses_previous_policy(self):
        store = Store(self.paths)
        controller = self.controller(store)
        for index in range(4):
            with patch("panel.store.time.strftime", return_value=f"backup-20261120-10000{index}"):
                store.automatic_backup()
        archives = {path.name: path.read_bytes() for path in store.backup_files()}
        with socket.socket() as temporary_port:
            temporary_port.bind(("127.0.0.1", 0))
            port = temporary_port.getsockname()[1]
        controller.operation("settings.save", {"port": port, "backup_keep": 1}, lambda *_: None)
        confirmation = store.paths.etc / "web-pending.json"
        self.assertTrue(confirmation.is_file())
        with patch("panel.store.time.strftime", return_value="backup-20261120-100009"):
            controller.operation("backup.create", {}, lambda *_: None)
        self.assertEqual(len(store.backup_files()), 5)
        pending = json.loads(confirmation.read_text())
        confirmation.write_text(json.dumps(dict(pending, deadline=0)))
        controller.tick()
        self.assertEqual(store.config()["settings"]["backup_keep"], 7)
        self.assertEqual(store.config()["settings"]["port"], 8787)
        self.assertEqual({name: (store.paths.backups / name).read_bytes() for name in archives}, archives)
        self.assertFalse(store.paths.staged_backup.exists())


if __name__ == "__main__":
    unittest.main()
