"""Home navigation, no duplicate confirmation on safe create, installer progress."""
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from pm2 import simple_ui


class StreamlinedPortsTests(unittest.TestCase):
    def test_normal_create_applies_without_second_confirmation(self):
        with (mock.patch.object(simple_ui.tunnels, "handle",
                                side_effect=[{"dry_run": True}, {"saved": True}]) as do,
              mock.patch.object(simple_ui, "_confirm") as confirm,
              redirect_stdout(io.StringIO()) as output):
            simple_ui._mutate("create", ["--mode", "ports"])
        self.assertEqual(do.call_count, 2)
        self.assertIn("--dry-run", do.call_args_list[0].args[1])
        self.assertNotIn("--dry-run", do.call_args_list[1].args[1])
        confirm.assert_not_called()
        self.assertIn("Applied", output.getvalue())

    def test_dangerous_all_except_still_requires_confirmation(self):
        with (mock.patch.object(simple_ui.tunnels, "handle",
                                return_value={"dry_run": True}) as do,
              mock.patch.object(simple_ui, "_confirm", return_value=False)
              as confirm, redirect_stdout(io.StringIO())):
            simple_ui._mutate("create", ["--mode", "all-except"])
        do.assert_called_once()
        confirm.assert_called_once_with("Forward nearly ALL ports, including new services?")

    def test_specific_port_edit_applies_without_silent_default_no(self):
        with (mock.patch.object(simple_ui.tunnels, "handle",
                                side_effect=[{"dry_run": True}, {"saved": True}]) as do,
              mock.patch.object(simple_ui, "_confirm") as confirm,
              redirect_stdout(io.StringIO())):
            simple_ui._mutate("update", ["--mode", "ports"])
        self.assertEqual(do.call_count, 2)
        confirm.assert_not_called()

    def test_delete_still_confirms(self):
        with (mock.patch.object(simple_ui.tunnels, "handle",
                                return_value={"dry_run": True}) as do,
              mock.patch.object(simple_ui, "_confirm", return_value=False)
              as confirm, redirect_stdout(io.StringIO())):
            simple_ui._mutate("delete", ["--mode", "ports"])
        do.assert_called_once()
        confirm.assert_called_once_with("Delete this connection permanently?")

    def test_all_except_update_still_confirms(self):
        with (mock.patch.object(simple_ui.tunnels, "handle",
                                return_value={"dry_run": True}) as do,
              mock.patch.object(simple_ui, "_confirm", return_value=False)
              as confirm, redirect_stdout(io.StringIO())):
            simple_ui._mutate("update", ["--mode", "all-except"])
        do.assert_called_once()
        confirm.assert_called_once_with("Forward nearly ALL ports, including new services?")

    def test_home_option_2_goes_to_unified_ports(self):
        with (mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_choose", side_effect=["2", "0"]),
              mock.patch.object(simple_ui, "_tunnel_page") as ports):
            self.assertEqual(simple_ui.menu(), 0)
        ports.assert_called_once()

    def test_home_option_3_goes_to_daily_report(self):
        with (mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_choose", side_effect=["3", "0"]),
              mock.patch.object(simple_ui, "_usage_report") as report):
            self.assertEqual(simple_ui.menu(), 0)
        report.assert_called_once()


if __name__ == "__main__":
    unittest.main()
