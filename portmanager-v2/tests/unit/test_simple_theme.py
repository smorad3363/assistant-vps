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

    def test_saved_connections_without_owned_nat_are_marked_not_applied(self):
        saved = {
            "id": "00000000-0000-4000-8000-000000000001",
            "name": "port-8086", "enabled": True, "mode": "ports",
            "listen_ip": "77.90.10.180", "interface": "eth0",
            "protocols": ["tcp", "udp"],
            "mapping": [{"listen_port": 8086, "target_port": 8086}],
            "exclude": [], "target_ip": "2.29.39.22",
        }
        with (mock.patch.object(simple_ui.config, "load",
                                return_value={"tunnels": [saved]}),
              mock.patch.object(simple_ui.system_rules, "detect_nat",
                                return_value=([], None)),
              redirect_stdout(io.StringIO()) as output):
            simple_ui._list_tunnels()
        shown = output.getvalue()
        self.assertIn("NOT APPLIED", shown)
        self.assertIn("sudo portmanager2 tunnel apply", shown)

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

    @staticmethod
    def usage_fixture():
        port_new = {"protocol": "tcp", "port": 8080,
                    "download_bytes_lower": 2_000_000_000,
                    "download_bytes_upper": 2_100_000_000,
                    "upload_bytes_lower": 1_000_000_000,
                    "upload_bytes_upper": 1_100_000_000,
                    "covered_seconds": 600, "missing_seconds": 60,
                    "boundary_uncertain_bytes": 200,
                    "overlapping_sources": False}
        port_old = dict(port_new, port=1001,
                        download_bytes_lower=300_000_000,
                        download_bytes_upper=300_000_000,
                        upload_bytes_lower=400_000_000,
                        upload_bytes_upper=400_000_000)
        network = {"interface": "eth0", "has_samples": True,
                   "download_bytes_lower": 2_000_000_000,
                   "download_bytes_upper": 2_100_000_000,
                   "upload_bytes_lower": 1_000_000_000,
                   "upload_bytes_upper": 1_100_000_000,
                   "covered_seconds": 600, "missing_seconds": 60}
        return {"ports": [port_new, port_old],
                "server": network,
                "daily": [
                    {"date": "2026-10-09", "ports": [port_old], "server": network},
                    {"date": "2026-10-10", "ports": [port_new], "server": network}],
                "timezone": "Asia/Tehran"}

    def test_home_four_shows_days_without_prompts(self):
        from datetime import datetime
        from zoneinfo import ZoneInfo
        zone = ZoneInfo("Asia/Tehran")
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title") as title,
              mock.patch.object(simple_ui, "_ask") as prompts,
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=data) as report,
              mock.patch.object(simple_ui, "_choose", return_value="0") as choose,
              redirect_stdout(io.StringIO())):
            before = datetime.now(zone)
            simple_ui._usage_report()
            after = datetime.now(zone)
        prompts.assert_not_called()
        self.assertEqual(title.call_args_list[-1].args[0], "TRAFFIC BY DAY")
        args = report.call_args.args
        self.assertEqual(args[2], "Asia/Tehran")
        self.assertIsNone(report.call_args.kwargs["port"])
        self.assertEqual(args[0], (before - simple_ui.timedelta(days=13))
                         .replace(hour=0, minute=0).strftime("%Y-%m-%d %H:%M"))
        self.assertIn(args[1], [
            before.replace(second=0, microsecond=0).strftime("%Y-%m-%d %H:%M"),
            after.replace(second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")])
        first_menu = choose.call_args.args
        self.assertIn("2026-10-10", first_menu[0][1])
        self.assertIn("2026-10-09", first_menu[1][1])

    def test_select_day_shows_only_its_ports_and_returns_to_dates(self):
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title") as titles,
              mock.patch.object(simple_ui, "_ask") as prompts,
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=data),
              mock.patch.object(simple_ui, "_choose",
                                side_effect=["1", "0", "0"]) as chooser,
              redirect_stdout(io.StringIO()) as out):
            simple_ui._usage_report()
        prompts.assert_not_called()
        self.assertEqual([call.args[0] for call in titles.call_args_list],
                         ["TRAFFIC BY DAY", "PORTS · 2026-10-10",
                          "TRAFFIC BY DAY"])
        output = out.getvalue()
        self.assertIn("TCP:8080", output)
        self.assertNotIn("TCP:1001", output)
        self.assertIn("SERVER TRAFFIC", output)
        self.assertIn("PORT BREAKDOWN", output)
        self.assertEqual(chooser.call_count, 3)
        self.assertIn("Back to days", str(chooser.call_args_list[1].args))

    def test_day_details_separate_colored_large_download_upload(self):
        data = self.usage_fixture()
        day = data["daily"][1]
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui.shutil, "get_terminal_size",
                                return_value=os.terminal_size((130, 45))),
              mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.dict(simple_ui.os.environ,
                              {"TERM": "xterm-256color"}, clear=False),
              mock.patch.object(simple_ui, "_choose", return_value="0"),
              redirect_stdout(io.StringIO()) as out):
            simple_ui._usage_detail(data, day)
        output = out.getvalue()
        self.assertIn("\033[92;1m", output)
        self.assertIn("\033[96;1m", output)
        self.assertIn("███", output)
        self.assertIn("↓ DOWNLOAD", output)
        self.assertIn("↑ UPLOAD", output)
        self.assertIn("TCP:8080", output)
        self.assertIn("2.00*", output)
        self.assertIn("1.00*", output)

    def test_partial_sample_shows_recorded_gb_and_possible_extra_not_dash_range(self):
        # Reproduces the exact symptom reported by the operator: a daily
        # range 37.35–37.87 was misread as subtraction.
        data = {
            "interface": "eth0", "has_samples": True,
            "download_bytes_lower": 37_350_000_000,
            "download_bytes_upper": 37_870_000_000,
            "upload_bytes_lower": 37_220_000_000,
            "upload_bytes_upper": 37_730_000_000,
            "covered_seconds": 71*60,
        }
        with (mock.patch.object(simple_ui.shutil, "get_terminal_size",
                                return_value=os.terminal_size((110, 29))),
              redirect_stdout(io.StringIO()) as out):
            simple_ui._usage_hero("SERVER TRAFFIC", data, 110)
        shown = out.getvalue()
        self.assertIn("↓ DOWNLOAD   37.35 GB recorded", shown)
        self.assertIn("↑ UPLOAD     37.22 GB recorded", shown)
        self.assertIn("74.57 GB recorded", shown)
        self.assertIn("↓ up to +0.52 GB", shown)
        self.assertIn("↑ up to +0.51 GB", shown)
        self.assertIn("not counted above", shown)
        self.assertNotIn("37.35–37.87", shown)
        self.assertNotIn("Partial sample: ↓", shown)

    def test_boundaries_are_marked_even_when_both_values_round_the_same(self):
        self.assertEqual(simple_ui._usage_amount(37_350_000_000,
                                                 37_870_000_000), "37.35*")
        self.assertEqual(simple_ui._usage_amount(2_000_000_000,
                                                 2_000_000_001), "2.00*")
        self.assertEqual(simple_ui._usage_amount(1_000_000, 2_000_000), "<0.01*")
        self.assertEqual(simple_ui._usage_amount(0, 100), "0*")
        self.assertEqual(simple_ui._usage_amount(1_000_000_000,
                                                 1_000_000_000), "1.00")
        self.assertEqual(simple_ui._usage_uncertain_extra(
            37_350_000_000, 37_870_000_000), "0.52")

    def test_short_terminal_suppresses_multiline_numbers(self):
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui.shutil, "get_terminal_size",
                                return_value=os.terminal_size((112, 29))),
              mock.patch.object(simple_ui, "_choose", return_value="0"),
              redirect_stdout(io.StringIO()) as out):
            simple_ui._usage_detail(data, data["daily"][1])
        self.assertIn("↓ DOWNLOAD   2.00 GB", out.getvalue())
        self.assertIn("↑ UPLOAD     1.00 GB", out.getvalue())
        self.assertNotIn("███", out.getvalue())

    def test_compact_usage_header_hides_unneeded_network_status(self):
        with (mock.patch.object(simple_ui, "_clear_screen"),
              redirect_stdout(io.StringIO()) as output):
            simple_ui._title("TRAFFIC BY DAY", compact=True)
        rendered = output.getvalue()
        self.assertIn("TRAFFIC BY DAY", rendered)
        self.assertNotIn("View: all ports / rules", rendered)
        self.assertNotIn("Mode: interactive", rendered)

    def test_previous_days_page_and_day_selection(self):
        data = self.usage_fixture()
        from datetime import date, timedelta
        data["daily"] = [
            {"date": (date(2026, 10, 14) - timedelta(days=i)).isoformat(),
             "server": {"has_samples": False}, "ports": []}
            for i in reversed(range(14))]
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=data),
              mock.patch.object(simple_ui, "_usage_detail") as detail,
              mock.patch.object(simple_ui, "_choose",
                                side_effect=["9", "1", "0"]) as chose,
              redirect_stdout(io.StringIO())):
            simple_ui._usage_report()
        self.assertEqual(detail.call_args.args[1]["date"], "2026-10-07")
        self.assertEqual(chose.call_count, 3)

    def test_inline_totals_and_compact_gb_are_visible_before_selecting_day(self):
        day = self.usage_fixture()["daily"][1]
        desc = simple_ui._usage_day_label(day, 160)
        self.assertIn("↓", desc)
        self.assertIn("↑", desc)
        self.assertIn("TOTAL", desc)
        self.assertIn("3.00*", desc)
        self.assertEqual(simple_ui._usage_amount(500_000, 500_000), "<0.01")
        self.assertEqual(simple_ui._usage_amount(2_000_000_000,
                                                2_000_000_001), "2.00*")
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=data),
              mock.patch.object(simple_ui, "_choose", return_value="0"),
              redirect_stdout(io.StringIO()) as shown):
            simple_ui._usage_report()
        self.assertIn("PERIOD TOTAL", shown.getvalue())
        self.assertIn("TOTAL", shown.getvalue())

    def test_multi_date_port_table_shows_date_port_download_upload_total(self):
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title") as title,
              mock.patch.object(simple_ui, "_choose", return_value="0"),
              mock.patch.object(simple_ui, "_ui_width", return_value=120),
              redirect_stdout(io.StringIO()) as shown):
            simple_ui._usage_cross_date(data)
        rendered = shown.getvalue()
        self.assertEqual(title.call_args.args[0], "PORT CONSUMPTION BY DATE")
        self.assertIn("2026-10-10", rendered)
        self.assertIn("TCP:8080", rendered)
        self.assertIn("2026-10-09", rendered)
        self.assertIn("TCP:1001", rendered)
        self.assertIn("2.00*", rendered)  # download for October 10
        self.assertIn("1.00*", rendered)  # upload for October 10
        self.assertIn("3.00*", rendered)  # total for October 10
        self.assertIn("0.30", rendered)       # October 9 download
        self.assertIn("0.40", rendered)       # October 9 upload
        self.assertIn("0.70", rendered)       # October 9 total
        self.assertIn("MEASURED", rendered)

    def test_multi_date_filter_one_port_never_substitutes_missing_day_zero(self):
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_choose",
                                side_effect=["f", "0"]),
              mock.patch.object(simple_ui, "_ask",
                                return_value="8080") as asked,
              redirect_stdout(io.StringIO()) as shown):
            simple_ui._usage_cross_date(data)
        output = shown.getvalue()
        asked.assert_called_once()
        self.assertIn("TCP:8080", output)
        self.assertIn("2026-10-09", output)
        self.assertIn("NO RECORD (unknown)", output)
        self.assertIn("RECORDED PERIOD TOTAL", output)
        self.assertNotIn("2026-10-09   0.00", output)

    def test_day_picker_and_day_detail_can_open_cross_date_port_history(self):
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=data),
              mock.patch.object(simple_ui, "_usage_cross_date") as cross,
              mock.patch.object(simple_ui, "_choose",
                                side_effect=["p", "0"]),
              redirect_stdout(io.StringIO())):
            simple_ui._usage_report()
        cross.assert_called_once_with(data)
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_usage_cross_date") as cross,
              mock.patch.object(simple_ui, "_choose",
                                side_effect=["p", "0"]),
              redirect_stdout(io.StringIO())):
            simple_ui._usage_detail(data, data["daily"][1])
        cross.assert_called_once_with(data)

    def test_multi_date_table_paginated_and_prints_no_data_days(self):
        data = self.usage_fixture()
        data["daily"] = [{"date": f"2026-10-{day:02d}",
                          "ports": ([data["ports"][0]] if day == 10 else [])}
                         for day in range(1, 11)]
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_choose",
                                side_effect=["9", "0"]) as menu,
              mock.patch.object(simple_ui.shutil, "get_terminal_size",
                                return_value=os.terminal_size((116, 21))),
              redirect_stdout(io.StringIO()) as shown):
            simple_ui._usage_cross_date(data)
        self.assertEqual(menu.call_count, 2)
        self.assertIn("NO RECORD (unknown)", shown.getvalue())
        self.assertIn("Page 2/", shown.getvalue())

    def test_day_list_seven_dates_has_unique_hotkeys_even_at_slots_three_four(self):
        from datetime import date, timedelta
        data = self.usage_fixture()
        data["daily"] = [
            {"date": (date(2026, 10, 14) - timedelta(days=i)).isoformat(),
             "server": {"has_samples": False}, "ports": []}
            for i in reversed(range(14))]
        real_choose = simple_ui._choose
        choice_calls = []
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui.os, "isatty", return_value=False),
              mock.patch.object(simple_ui, "_ask", return_value="0"),
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=data),
              mock.patch.object(simple_ui, "_usage_detail") as show_day,
              redirect_stdout(io.StringIO())):
            def check_choose(*options, **kwargs):
                keys = [key for key, _ in options]
                self.assertEqual(len(keys), len(set(keys)))
                self.assertIn("3", keys)
                self.assertIn("4", keys)
                self.assertNotIn("s", keys)
                self.assertNotIn("t", keys)
                choice_calls.append(keys)
                self.assertEqual(kwargs.get("shortcuts"), ("s", "t", "p"))
                real_choose(*options, **kwargs)  # verify the real menu contract
                return "4" if len(choice_calls) == 1 else "0"
            with mock.patch.object(simple_ui, "_choose", side_effect=check_choose):
                simple_ui._usage_report()
        self.assertEqual(len(choice_calls), 2)
        self.assertEqual(show_day.call_args.args[1]["date"], "2026-10-11")

    def test_letters_work_as_menu_shortcuts_and_keep_terminal_restored(self):
        import termios
        import tty
        options = (("1", "Today"), ("2", "Yesterday"),
                   ("s", "Settings"), ("t", "Totals"), ("0", "Back"))
        with (mock.patch.object(simple_ui.sys, "stdin", mock.Mock(
                  fileno=mock.Mock(return_value=0))),
              mock.patch.object(simple_ui.os, "read", return_value=b"T"),
              mock.patch.object(termios, "tcgetattr", return_value=[0]*7),
              mock.patch.object(termios, "tcsetattr") as restored,
              mock.patch.object(tty, "setcbreak"),
              redirect_stdout(io.StringIO())):
            result = simple_ui._menu_key(options, selected=0)
        self.assertEqual(result, "t")
        restored.assert_called_once()

    def test_no_samples_never_displays_fictitious_zero_server_total(self):
        data = self.usage_fixture()
        data["server"] = {"interface": "eth0", "has_samples": False}
        data["daily"][1]["server"] = data["server"]
        data["daily"][1]["ports"] = []
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_choose", return_value="0"),
              redirect_stdout(io.StringIO()) as out):
            simple_ui._usage_detail(data, data["daily"][1])
        self.assertIn("NOT RECORDED", out.getvalue())
        self.assertIn("Usage is unknown, not 0 GB", out.getvalue())

    def test_custom_range_prompts_only_on_explicit_change(self):
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_ask", side_effect=[
                  "Asia/Tehran", "2026-10-09 00:00",
                  "2026-10-10 12:00", "1001"]) as prompts,
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=data) as report,
              mock.patch.object(simple_ui, "_choose",
                                side_effect=["s", "0"]),
              redirect_stdout(io.StringIO())):
            simple_ui._usage_report()
        self.assertEqual(prompts.call_count, 4)
        report.assert_any_call(
            "2026-10-09 00:00", "2026-10-10 12:00",
            "Asia/Tehran", port=1001)

    def test_range_totals_still_available_but_not_in_main_day_view(self):
        data = self.usage_fixture()
        with (mock.patch.object(simple_ui, "_title") as titles,
              mock.patch.object(simple_ui.usage_ledger, "report",
                                return_value=data),
              mock.patch.object(simple_ui, "_choose",
                                side_effect=["t", "0", "0"]),
              redirect_stdout(io.StringIO()) as output):
            simple_ui._usage_report()
        self.assertEqual([call.args[0] for call in titles.call_args_list],
                         ["TRAFFIC BY DAY", "PORTS · SELECTED PERIOD",
                          "TRAFFIC BY DAY"])
        self.assertIn("PORT BREAKDOWN", output.getvalue())
        self.assertIn("↓ DOWNLOAD", output.getvalue())

    def test_fixed_width_port_columns_and_compact_layout(self):
        row = self.usage_fixture()["ports"][0]
        with (mock.patch.object(simple_ui, "_title"),
              mock.patch.object(simple_ui, "_ui_width", return_value=85),
              mock.patch.object(simple_ui, "_choose", return_value="0"),
              redirect_stdout(io.StringIO()) as out):
            simple_ui._usage_detail(self.usage_fixture(),
                                    self.usage_fixture()["daily"][1])
        self.assertIn("TCP:8080", out.getvalue())
        self.assertIn("2.00*", out.getvalue())
        self.assertIn("1.00*", out.getvalue())
        self.assertNotIn("███", out.getvalue())
        self.assertEqual(len(simple_ui._usage_big_digits("2.23")), 5)

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
