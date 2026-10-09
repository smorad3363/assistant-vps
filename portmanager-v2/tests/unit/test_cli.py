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
        self.assertIn("2.0.0-dev.1", out)

    def test_unimplemented_tunnel_fails_closed(self):
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli, "ETC", Path(t) / "etc"):
                code, out, err = self.invoke([
                    "tunnel", "create", "--name", "not-ready",
                ])
                self.assertEqual(code, 8)
                self.assertIn("E_UNSUPPORTED", err)
                self.assertFalse((Path(t) / "etc").exists())

    def test_unimplemented_network_commands(self):
        for args in (["tunnel", "apply"], ["restore"], ["sample"],
                     ["limits", "set", "--tunnel", "abc"],
                     ["backup", "create"]):
            code, _, err = self.invoke(args)
            self.assertEqual(code, 8, args)
            self.assertIn("E_UNSUPPORTED", err)

    def test_status_json_contract(self):
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli, "ETC", Path(t) / "etc"):
                code, out, err = self.invoke(["status", "--json"])
                self.assertEqual(code, 0)
                self.assertEqual(err, "")
                obj = json.loads(out)
                self.assertEqual(set(obj), {"ok", "code", "message", "details", "request_id"})
                self.assertEqual(obj["details"]["version"], "2.0.0-dev.1")

    def test_limits_list_never_claims_shaping_support(self):
        code, out, _ = self.invoke(["limits", "list", "--json"])
        self.assertEqual(code, 0)
        obj = json.loads(out)
        self.assertFalse(obj["details"]["supported"])
        self.assertEqual(obj["details"]["reason"], "planned_for_2.1")

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
