"""Minimal terminal menus: no instruction footer and direct numeric actions."""
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from pm2 import simple_ui


class CompactNavigationTests(unittest.TestCase):
    def test_no_navigation_hints_in_any_shared_menu(self):
        with redirect_stdout(io.StringIO()) as out:
            simple_ui._ui_actions(("1", "Add tunnel"), ("2", "All except"),
                                  ("0", "Back"))
        shown = out.getvalue()
        self.assertIn("Add tunnel", shown)
        self.assertNotIn("Move", shown)
        self.assertNotIn("Enter Choose", shown)
        self.assertNotIn("Number + Enter", shown)

    def test_single_digit_activates_without_enter(self):
        import termios
        import tty
        choices = (("1", "Add tunnel"), ("2", "All except"),
                   ("0", "Back"))
        with (mock.patch.object(simple_ui.sys, "stdin",
                                mock.Mock(fileno=mock.Mock(return_value=0))),
              mock.patch.object(simple_ui.os, "read", return_value=b"2") as reads,
              mock.patch.object(termios, "tcgetattr", return_value=[0] * 7),
              mock.patch.object(termios, "tcsetattr") as restore,
              mock.patch.object(tty, "setcbreak"),
              redirect_stdout(io.StringIO())):
            selected = simple_ui._menu_key(choices, selected=0)
        self.assertEqual(selected, "2")
        reads.assert_called_once()
        restore.assert_called_once()

    def test_empty_enter_chooses_highlighted_arrow_item(self):
        import termios
        import tty
        choices = (("1", "Add tunnel"), ("2", "All except"),
                   ("0", "Back"))
        with (mock.patch.object(simple_ui.sys, "stdin",
                                mock.Mock(fileno=mock.Mock(return_value=0))),
              mock.patch.object(simple_ui.os, "read", return_value=b"\r"),
              mock.patch.object(termios, "tcgetattr", return_value=[0] * 7),
              mock.patch.object(termios, "tcsetattr"),
              mock.patch.object(tty, "setcbreak"),
              redirect_stdout(io.StringIO())):
            self.assertEqual(simple_ui._menu_key(choices, selected=1), "2")

    def test_arrow_repaint_accounts_for_removed_footer(self):
        with redirect_stdout(io.StringIO()) as out:
            simple_ui._repaint_actions((("1", "A"), ("2", "B")), 1, "")
        self.assertIn("\x1b[4A\x1b[J", out.getvalue())


if __name__ == "__main__":
    unittest.main()
