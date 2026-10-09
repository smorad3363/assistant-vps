"""Phase-1 tests: CLI must fail closed and never touch real network state."""
import contextlib
import io
import json
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from pm2 import cli


class CLITests(TestCase):
    def invoke(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = cli.main(arguments)
            except SystemExit as exc:
                code = int(exc.code)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_version(self):
        code, out, _ = self.invoke(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("2.1.0-rc.4", out)

    def test_unimplemented_tunnel_fails_closed(self):
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli, "ETC", Path(t) / "etc"):
                code, out, err = self.invoke([
                    "tunnel", "create", "--name", "not-ready",
                ])
                self.assertEqual(code, 2)
                self.assertIn("E_VALIDATION", err)
                self.assertFalse((Path(t) / "etc").exists())

    def test_unimplemented_admin_operations_fail_closed(self):
        code, _, err = self.invoke(["limits", "set", "--tunnel", "abc"])
        self.assertIn(code, (5, 8))
        self.assertTrue("E_UNSUPPORTED" in err or "E_CONFLICT" in err)
        with mock.patch("pm2.guard.os.geteuid", return_value=1000):
            code, _, err = self.invoke(["confirm", "nonexistent"])
        self.assertEqual(code, 3)
        self.assertIn("E_PERMISSION", err)
        with mock.patch("pm2.backup.os.geteuid", return_value=1000):
            code, _, err = self.invoke(["backup", "create"])
        self.assertEqual(code, 3)
        self.assertIn("E_PERMISSION", err)

    def test_report_window_json_is_parsed(self):
        with mock.patch("pm2.sampler.report", return_value={
            "window": "1h", "coverage_seconds": 0, "tunnels": []
        }) as called:
            code, out, err = self.invoke(["report", "--window", "1h", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(json.loads(out)["ok"])
        called.assert_called_once_with("1h")

    def test_tunnel_list_validates_persisted_config(self):
        with tempfile.TemporaryDirectory() as t:
            from pm2 import transaction
            base = Path(t)
            (base / "config.json").write_text(
                '{"schema_version":1,"generation":0,"tunnels":[]}')
            with mock.patch.object(transaction, "CONFIG", base / "config.json"):
                code, out, _ = self.invoke(["tunnel", "list", "--json"])
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)["details"]["tunnels"], [])

    def test_status_json_contract(self):
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli, "ETC", Path(t) / "etc"):
                code, out, err = self.invoke(["status", "--json"])
                self.assertEqual(code, 0)
                self.assertEqual(err, "")
                obj = json.loads(out)
                self.assertEqual(set(obj), {"ok", "code", "message", "details", "request_id"})
                self.assertEqual(obj["details"]["version"], "2.1.0-rc.4")

    def test_schedule_preview_is_json_and_does_not_call_tc_or_iptables(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "windows.json"
            schedule = {"schema_version": 1, "policies": [{
                "id": "evening", "port": 443, "protocol": "tcp,udp",
                "timezone": "UTC", "days": [0], "start": "18:00", "end": "23:00",
                "download_mbps": 20, "upload_mbps": 10, "enabled": True
            }]}
            path.write_text(json.dumps(schedule))
            with mock.patch("pm2.discovery.run",
                            side_effect=AssertionError("read-only preview called network")):
                code, out, err = self.invoke([
                    "limits", "schedule-preview", "--file", str(path),
                    "--at", "2026-10-12T20:00:00Z", "--json"])
            self.assertEqual(code, 0, err)
            payload = json.loads(out)
            self.assertTrue(payload["ok"])
            self.assertFalse(payload["details"]["network_mutation"])
            self.assertEqual(payload["details"]["would_apply"][0]["port"], 443)
            self.assertEqual(json.loads(path.read_text()), schedule)

    def test_schedule_install_wires_kernel_reconcile_and_minute_timer(self):
        with (mock.patch.object(cli, "mutation_lock", return_value=contextlib.nullcontext()),
              mock.patch("pm2.shaping.install_schedule", return_value={"saved": 1}) as installed,
              mock.patch("pm2.shaping.reconcile", return_value={"changed": True, "active_filters": 2}) as applied,
              mock.patch("pm2.services.activate") as activated):
            code, out, err = self.invoke(["limits", "schedule-install",
                                          "--file", "/tmp/plan.json", "--json"])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["details"]["active_filters"], 2)
        installed.assert_called_once_with("/tmp/plan.json")
        applied.assert_called_once_with()
        activated.assert_called_once()

    def test_schedule_install_failure_does_not_claim_activation(self):
        from pm2.errors import PM2Error
        with (mock.patch.object(cli, "mutation_lock", return_value=contextlib.nullcontext()),
              mock.patch("pm2.shaping.install_schedule",
                         side_effect=PM2Error("E_CONFLICT", "foreign V1 tc")),
              mock.patch("pm2.services.activate") as activated):
            code, out, err = self.invoke(["limits", "schedule-install",
                                          "--file", "/tmp/plan.json"])
        self.assertNotEqual(code, 0)
        self.assertIn("E_CONFLICT", err)
        activated.assert_not_called()

    def test_limits_list_reports_owned_policies_not_foreign_tc(self):
        with (mock.patch("pm2.shaping.schedule_load", return_value={"schema_version": 1, "policies": []}),
              mock.patch("pm2.shaping.state_load", return_value={"product": "portmanager2", "interfaces": [], "filters": []})):
            code, out, _ = self.invoke(["limits", "list", "--json"])
        self.assertEqual(code, 0)
        obj = json.loads(out)
        self.assertTrue(obj["details"]["supported"])
        self.assertEqual(obj["details"]["policies"], [])
        self.assertEqual(obj["details"]["active_filters"], 0)

    def test_uninstall_dry_run_has_no_mutations(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t)
            opt, etc = base / "opt", base / "etc"
            opt.mkdir()
            etc.mkdir()
            (opt / ".owner.json").write_text('{"product":"portmanager2"}')
            (etc / "owner.json").write_text('{"product":"portmanager2"}')
            with (mock.patch.object(cli, "OPT", opt),
                  mock.patch.object(cli, "ETC", etc),
                  mock.patch.object(cli, "BIN", base / "bin"),
                  mock.patch.object(cli, "DATA", base / "data"),
                  mock.patch.object(cli, "LOG", base / "log")):
                code, out, _ = self.invoke(["uninstall", "--dry-run"])
                self.assertEqual(code, 0)
                self.assertTrue(opt.exists())
                self.assertTrue(etc.exists())
                self.assertIn("would_remove", out)

    def test_uninstall_rejects_unowned_dir(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t)
            etc = base / "etc"
            etc.mkdir()
            with (mock.patch.object(cli, "ETC", etc),
                  mock.patch.object(cli, "OPT", base / "opt"),
                  mock.patch.object(cli, "BIN", base / "bin")):
                code, _, err = self.invoke(["uninstall", "--dry-run"])
                self.assertEqual(code, 5)
                self.assertIn("E_CONFLICT", err)

    def test_mutation_lock_rejects_parallel_writer(self):
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli, "LOCK", Path(t) / "pm2.lock"):
                with cli.mutation_lock():
                    with self.assertRaises(cli.PM2Error) as caught:
                        with cli.mutation_lock():
                            pass
                self.assertEqual(caught.exception.code, "E_LOCKED")

    def test_invalid_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as t:
            etc = Path(t)
            (etc / "config.json").write_text('{"schema_version":99,"tunnels":[]}')
            with mock.patch.object(cli, "ETC", etc):
                code, _, err = self.invoke(["status"])
                self.assertEqual(code, 8)
                self.assertIn("E_UNSUPPORTED", err)
