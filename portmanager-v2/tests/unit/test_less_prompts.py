"""Direct port actions without redundant confirmations, with watchdog handshake."""
import contextlib
import io
import os
import unittest
from unittest import mock

from pm2 import simple_ui


class NoPromptsTests(unittest.TestCase):
    def setUp(self):
        simple_ui._PENDING_MENU_ACK = None

    def tearDown(self):
        simple_ui._PENDING_MENU_ACK = None

    def test_regular_create_edit_delete_do_not_request_confirmation(self):
        for operation in ("create", "update", "delete"):
            with self.subTest(operation=operation):
                with (mock.patch.object(simple_ui.tunnels, "handle",
                                        side_effect=[{"dry_run": True},
                                                     {"changed": True}]) as do,
                      mock.patch.object(simple_ui, "_ask") as ask,
                      contextlib.redirect_stdout(io.StringIO())):
                    simple_ui._mutate(operation, ["--mode", "ports"])
                self.assertEqual(do.call_count, 2)
                ask.assert_not_called()
                self.assertEqual("--yes" in do.call_args_list[-1].args[1],
                                 operation == "delete")

    def test_all_except_creates_and_updates_without_yes_no(self):
        for operation in ("create", "update"):
            with self.subTest(operation=operation):
                with (mock.patch.object(simple_ui.tunnels, "handle",
                                        side_effect=[{"dry_run": True},
                                                     {"changed": True}]) as do,
                      mock.patch.object(simple_ui, "_ask") as ask,
                      contextlib.redirect_stdout(io.StringIO())):
                    simple_ui._mutate(operation, ["--mode", "all-except"])
                self.assertEqual(do.call_count, 2)
                ask.assert_not_called()

    def test_high_risk_edit_keeps_watchdog_until_next_real_action(self):
        token = "guard-token"
        with (mock.patch.object(simple_ui.tunnels, "handle",
                                side_effect=[{"dry_run": True},
                                             {"pending_confirmation": token}]),
              mock.patch.object(simple_ui.guard, "confirm") as confirm,
              contextlib.redirect_stdout(io.StringIO())):
            simple_ui._mutate("create", ["--mode", "all-except"])
            confirm.assert_not_called()
            self.assertEqual(simple_ui._PENDING_MENU_ACK, ("managed", token))

            with (contextlib.redirect_stdout(io.StringIO()),
                  mock.patch.object(simple_ui.os, "isatty", return_value=True),
                  mock.patch.object(simple_ui.sys.stdin, "isatty", return_value=True),
                  mock.patch.object(simple_ui.sys.stdout, "isatty", return_value=True),
                  mock.patch.object(simple_ui, "_ui_actions"),
                  mock.patch.object(simple_ui, "_draw_menu_prompt"),
                  mock.patch.object(simple_ui, "_menu_key", return_value="0"),
                  mock.patch("pm2.cli.mutation_lock",
                             return_value=contextlib.nullcontext()),
                  mock.patch.dict(os.environ, {"TERM": "xterm"})):
                self.assertEqual(simple_ui._choose(("0", "Back")), "0")
            confirm.assert_called_once_with(token)
            self.assertIsNone(simple_ui._PENDING_MENU_ACK)

    def test_terminal_loss_or_eof_does_not_confirm(self):
        simple_ui._PENDING_MENU_ACK = ("managed", "guard-token")
        with (mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.object(simple_ui.sys.stdin, "isatty", return_value=True),
              mock.patch.object(simple_ui.sys.stdout, "isatty", return_value=True),
              mock.patch.object(simple_ui, "_ui_actions"),
              mock.patch.object(simple_ui, "_draw_menu_prompt"),
              mock.patch.object(simple_ui, "_menu_key", return_value=None),
              mock.patch.object(simple_ui.guard, "confirm") as confirm,
              mock.patch.dict(os.environ, {"TERM": "xterm"})):
            self.assertIsNone(simple_ui._choose(("0", "Back")))
        confirm.assert_not_called()
        self.assertIsNotNone(simple_ui._PENDING_MENU_ACK)

    def test_noninteractive_input_never_completes_guarded_action(self):
        simple_ui._PENDING_MENU_ACK = ("managed", "guard-token")
        with (mock.patch.object(simple_ui.os, "isatty", return_value=False),
              mock.patch.object(simple_ui, "_ask", return_value="0"),
              mock.patch.object(simple_ui.guard, "confirm") as confirm,
              contextlib.redirect_stdout(io.StringIO())):
            self.assertEqual(simple_ui._choose(("0", "Back")), "0")
        confirm.assert_not_called()

    def test_external_nat_uses_same_menu_liveness_handshake(self):
        simple_ui._PENDING_MENU_ACK = ("foreign", "nat-token")
        with (mock.patch.object(simple_ui.nat_editor, "confirm") as confirm,
              mock.patch("pm2.cli.mutation_lock",
                         return_value=contextlib.nullcontext())):
            simple_ui._ack_on_next_menu_action()
        confirm.assert_called_once_with("nat-token")
        self.assertIsNone(simple_ui._PENDING_MENU_ACK)

    def test_home_option_2_goes_to_ports(self):
        with (mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_choose", side_effect=["2", "0"]),
              mock.patch.object(simple_ui, "_tunnel_page") as ports):
            self.assertEqual(simple_ui.menu(), 0)
        ports.assert_called_once()


if __name__ == "__main__":
    unittest.main()
