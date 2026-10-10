"""Regression checks for requested simple UI, unknown traffic and NAT rule visibility."""
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from pm2 import live_screen, simple_ui, system_rules
from pm2.errors import PM2Error


class FakeCurses:
    A_BOLD = 1
    def has_colors(self):
        return False
    class error(Exception):
        pass


class FakeScreen:
    def __init__(self):
        self.lines = []
        self.refreshes = 0
    def getmaxyx(self):
        return 28, 115
    def erase(self):
        self.lines.clear()
    def addnstr(self, y, x, text, maxlen, attr=0):
        self.lines.append((y, text[:maxlen]))
    def refresh(self):
        self.refreshes += 1


class NewThemeTest(unittest.TestCase):
    def test_two_cards_and_untracked_estimate_on_one_screen(self):
        screen = live_screen.LiveScreen(5)
        screen.window = FakeScreen()
        screen.curses = FakeCurses()
        row = {"protocol": "tcp", "listen_port": 8080, "now_up_mbps": 150,
               "now_down_mbps": 200, "avg10m_up_mbps": 150,
               "avg10m_down_mbps": 200, "averages": {},
               "graph_up": "▁▆█"}
        with redirect_stdout(io.StringIO()) as capture:
            screen.draw({"rows": [row], "interfaces": [{
                "interface": "eth0", "rx_mbps": 650, "tx_mbps": 640}]})
            screen.draw()
        display = "\n".join(s for _, s in screen.window.lines)
        self.assertEqual(capture.getvalue(), "")
        self.assertIn("DOWNLOAD", display)
        self.assertIn("UPLOAD", display)
        self.assertIn("TCP:8080", display)
        self.assertIn("OTHER / UNKNOWN", display)
        self.assertIn("450.0", display)
        self.assertIn("490.0", display)
        self.assertEqual(screen.window.refreshes, 2)

    def test_tracked_more_than_interface_never_negative(self):
        down, up = live_screen.LiveScreen.untracked_rates(
            {"rx_mbps": 100, "tx_mbps": 100},
            [{"now_down_mbps": 150, "now_up_mbps": 130}])
        self.assertEqual((down, up), (0, 0))

    def test_terminal_navigation_clears_previous_screen(self):
        with (mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.dict(simple_ui.os.environ, {"TERM": "xterm-256color"}),
              redirect_stdout(io.StringIO()) as output):
            simple_ui._clear_screen()
        self.assertEqual(output.getvalue(), chr(27) + "[2J" + chr(27) + "[H")

    def test_ports_menu_displays_nat_without_entering_config(self):
        old = {"chain": "PREROUTING", "protocol": "tcp", "port": "1001",
               "target": "DNAT", "destination": "203.0.113.1:4343"}
        with (mock.patch.object(simple_ui.config, "load",
                                return_value={"tunnels": []}),
              mock.patch.object(simple_ui.system_rules, "detect_nat",
                                return_value=([old], None)),
              mock.patch.object(simple_ui, "_ask", return_value="0"),
              redirect_stdout(io.StringIO()) as output):
            simple_ui._tunnel_page()
        self.assertIn("tcp:1001", output.getvalue())
        self.assertIn("203.0.113.1:4343", output.getvalue())
        self.assertIn("0 saved connections", output.getvalue())

    def test_keyboard_down_then_enter_selects_second_option(self):
        import termios
        import tty
        keys = [b"\x1b", b"[", b"B", b"\n"]
        choices = (("1", "Traffic"), ("2", "Ports"), ("0", "Exit"))
        with (mock.patch.object(simple_ui.sys, "stdin", mock.Mock(
                  fileno=mock.Mock(return_value=0))),
              mock.patch.object(simple_ui.os, "read", side_effect=keys),
              mock.patch("select.select", return_value=([0], [], [])),
              mock.patch.object(termios, "tcgetattr", return_value=[0]*7),
              mock.patch.object(termios, "tcsetattr") as restored,
              mock.patch.object(tty, "setcbreak"),
              mock.patch.object(simple_ui, "_repaint_actions"),
              redirect_stdout(io.StringIO())):
            result = simple_ui._menu_key(choices, selected=0)
        self.assertEqual(result, "2")
        restored.assert_called_once()

    def test_number_and_enter_select_direct_option(self):
        import termios
        import tty
        with (mock.patch.object(simple_ui.sys, "stdin", mock.Mock(
                  fileno=mock.Mock(return_value=0))),
              mock.patch.object(simple_ui.os, "read", side_effect=[b"3", b"\r"]),
              mock.patch.object(termios, "tcgetattr", return_value=[0]*7),
              mock.patch.object(termios, "tcsetattr") as restored,
              mock.patch.object(tty, "setcbreak"),
              redirect_stdout(io.StringIO())):
            result = simple_ui._menu_key(
                (("1", "Traffic"), ("3", "Edit"), ("0", "Back")), 0)
        self.assertEqual(result, "3")
        restored.assert_called_once()

    def test_escape_returns_safely_and_restores_tty(self):
        import termios
        import tty
        with (mock.patch.object(simple_ui.sys, "stdin", mock.Mock(
                  fileno=mock.Mock(return_value=0))),
              mock.patch.object(simple_ui.os, "read", return_value=b"\x1b"),
              mock.patch("select.select", return_value=([], [], [])),
              mock.patch.object(termios, "tcgetattr", return_value=[0]*7),
              mock.patch.object(termios, "tcsetattr") as restored,
              mock.patch.object(tty, "setcbreak"),
              redirect_stdout(io.StringIO())):
            result = simple_ui._menu_key((("1", "Traffic"), ("0", "Back")), 0)
        self.assertEqual(result, "0")
        restored.assert_called_once()

    def test_selected_menu_text_is_high_contrast_without_filled_background(self):
        with (mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.dict(simple_ui.os.environ, {"TERM": "xterm-256color"},
                              clear=False),
              redirect_stdout(io.StringIO()) as output):
            simple_ui._ui_actions(("1", "Traffic"), ("2", "Ports"),
                                  ("0", "Exit"), selected=1)
        text = output.getvalue()
        self.assertIn("\x1b[96;1m", text)
        self.assertNotIn("\x1b[30;46", text)

    def test_arrow_marker_changes_with_selected_row(self):
        with redirect_stdout(io.StringIO()) as output:
            simple_ui._ui_actions(("1", "Traffic"), ("2", "Ports"),
                                  ("0", "Exit"), selected=1)
        lines = output.getvalue().splitlines()
        self.assertTrue(any("▶" in line and "[2]" in line for line in lines))
        self.assertFalse(any("▶" in line and "[1]" in line for line in lines))

    def test_long_lists_have_next_pages_and_arrow_selection(self):
        entries = [{"name": f"Port-{i}"} for i in range(15)]
        with (mock.patch.object(simple_ui.shutil, "get_terminal_size",
                                return_value=os.terminal_size((100, 36))),
              mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_choose", side_effect=["9", "2"])
              as picked,
              redirect_stdout(io.StringIO())):
            selected = simple_ui._pick_row(
                "SAVED PORTS", entries, lambda item: item["name"])
        self.assertEqual(selected["name"], "Port-8")
        self.assertEqual(picked.call_count, 2)

    def test_daily_usage_is_default_and_directional_columns_are_distinct(self):
        port = {"protocol": "tcp", "port": 8080,
                "download_bytes_lower": 3_000_000_000,
                "download_bytes_upper": 3_100_000_000,
                "upload_bytes_lower": 1_000_000_000,
                "upload_bytes_upper": 1_100_000_000,
                "missing_seconds": 60, "boundary_uncertain_bytes": 200,
                "overlapping_sources": False}
        result = {"ports": [port], "daily": [
            {"date": "2026-10-10", "ports": [port]},
            {"date": "2026-10-11", "ports": [], "period_seconds": 86400}
        ]}
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_ask", side_effect=[
                  "Asia/Tehran", "2026-10-10 00:00",
                  "2026-10-12 00:00", "8080"]),
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=result) as called,
              mock.patch.object(simple_ui, "_choose", return_value="0") as chooser,
              redirect_stdout(io.StringIO()) as out):
            simple_ui._usage_report()
        called.assert_called_once_with(
            "2026-10-10 00:00", "2026-10-12 00:00",
            "Asia/Tehran", port=8080)
        rendered = out.getvalue()
        self.assertIn("DAILY", rendered)
        self.assertIn("DOWNLOAD", rendered)
        self.assertIn("UPLOAD", rendered)
        self.assertIn("3.0000", rendered)
        self.assertIn("1.0000", rendered)
        self.assertIn("2026-10-11", rendered)
        self.assertIn("No stored measurements", rendered)
        self.assertTrue(any("Show full period totals" in str(choice)
                            for call in chooser.call_args_list
                            for choice in call.args))

    def test_can_switch_from_daily_to_period_totals(self):
        port = {"protocol": "tcp", "port": 1001,
                "download_bytes_lower": 2_000_000_000,
                "download_bytes_upper": 2_000_000_000,
                "upload_bytes_lower": 1_000_000_000,
                "upload_bytes_upper": 1_000_000_000,
                "missing_seconds": 0, "boundary_uncertain_bytes": 0,
                "overlapping_sources": False}
        result = {"ports": [port], "daily": [
            {"date": "2026-10-10", "ports": [port]}]}
        with (mock.patch.object(simple_ui, "_title") as titles,
              mock.patch.object(simple_ui, "_ask", side_effect=[
                  "UTC", "2026-10-10 00:00", "2026-10-11 00:00", "ALL"]),
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=result),
              mock.patch.object(simple_ui, "_choose", side_effect=["4", "0"]),
              redirect_stdout(io.StringIO())):
            simple_ui._usage_report()
        self.assertEqual(titles.call_args_list[-2].args[0], "DAILY PORT USAGE")
        self.assertEqual(titles.call_args_list[-1].args[0], "PORT USAGE TOTALS")

    def test_usage_menu_queries_exact_user_time_range(self):
        report = {"ports": [{
            "protocol": "tcp", "port": 8080,
            "download_bytes_lower": 2_000_000_000,
            "download_bytes_upper": 2_100_000_000,
            "upload_bytes_lower": 1_000_000_000,
            "upload_bytes_upper": 1_100_000_000,
            "missing_seconds": 90, "boundary_uncertain_bytes": 200,
            "overlapping_sources": False,
        }]}
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_ask", side_effect=[
                  "Asia/Tehran", "2026-10-10 08:00",
                  "2026-10-10 10:00", "8080"]),
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=report) as called,
              mock.patch.object(simple_ui, "_choose", return_value="0"),
              redirect_stdout(io.StringIO()) as out):
            simple_ui._usage_report()
        called.assert_called_once_with(
            "2026-10-10 08:00", "2026-10-10 10:00",
            "Asia/Tehran", port=8080)
        self.assertIn("2.0000", out.getvalue())
        self.assertIn("Unrecorded:", out.getvalue())

    def test_iptables_nat_includes_old_rules_but_only_readonly(self):
        text = (
            "-A PREROUTING -i eth0 -p tcp -m tcp --dport 8080 -j DNAT "
            "--to-destination 203.0.113.1:80\n"
            "-A POSTROUTING -j MASQUERADE\n"
            "-A PREROUTING -p tcp --dport 22 -j ACCEPT\n")
        rules = system_rules.parse_nat(text)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["port"], "8080")
        self.assertEqual(rules[0]["destination"], "203.0.113.1:80")
        self.assertEqual(rules[1]["target"], "MASQUERADE")
        self.assertEqual(rules[0]["source"], "iptables (read-only)")
        self.assertEqual(rules[0]["interface"], "eth0")

    def test_menu_lists_detected_rule_even_if_v2_has_no_configs(self):
        fake = {"tunnels": []}
        old_rule = {"chain": "PREROUTING", "protocol": "tcp", "port": "8080",
                    "target": "DNAT", "destination": "203.0.113.1:80"}
        with (mock.patch.object(simple_ui.config, "load", return_value=fake),
              mock.patch.object(simple_ui.system_rules, "detect_nat",
                                return_value=([old_rule], None)),
              redirect_stdout(io.StringIO()) as output):
            self.assertEqual(simple_ui._list_tunnels(), [])
        self.assertIn("203.0.113.1:80", output.getvalue())
        self.assertIn("read-only", output.getvalue())


if __name__ == "__main__":
    unittest.main()
