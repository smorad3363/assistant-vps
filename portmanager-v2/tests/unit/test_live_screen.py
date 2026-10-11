"""Interactive live screen contract: in-place refresh, keyboard, compact ranking."""
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from pm2 import live_screen


def sample():
    def row(port, now, avg):
        return {"listen_port": port, "protocol": "tcp", "name": "local",
                "now_up_mbps": now, "now_down_mbps": 0.0,
                "avg10m_up_mbps": avg, "avg10m_down_mbps": 0.0,
                "averages": {key: {"up_mbps": avg, "down_mbps": 0.0,
                                  "coverage_seconds": 20}
                             for key in ("10m", "1h", "8h", "24h")},
                "graph_up": "   ▁▃█", "graph_down": "   ▁▁▂"}
    return {"rows": [row(8080, 200, 175), row(22, .08, .03),
                     row(8085, 0, 0), row(8086, 0, 0)],
            "interfaces": [{"interface": "eth0", "rx_mbps": 550.0,
                            "tx_mbps": 490.0}],
            "port_coverage": "selected_ipv4_listening_ports"}


class FakeCurses:
    A_BOLD = 0x20000
    KEY_UP = 259
    KEY_DOWN = 258
    KEY_RESIZE = 410
    def has_colors(self):
        return False
    class error(Exception):
        pass


class FakeWindow:
    def __init__(self, keys=()):
        self.writes = []
        self.erases = 0
        self.refreshes = 0
        self.keys = list(keys)
    def getmaxyx(self):
        return (24, 100)
    def erase(self):
        self.erases += 1
        self.writes.clear()
    def addnstr(self, y, x, value, length, *attributes):
        self.writes.append((y, x, value[:length]))
    def refresh(self):
        self.refreshes += 1
    def getch(self):
        return self.keys.pop(0) if self.keys else ord("q")


class LiveScreenTests(unittest.TestCase):
    def make_view(self, keys=()):
        view = live_screen.LiveScreen(5)
        view.window = FakeWindow(keys)
        view.curses = FakeCurses()
        return view

    def test_repeated_updates_erase_single_screen_not_print_new_tables(self):
        screen = self.make_view()
        with redirect_stdout(io.StringIO()) as output:
            screen.draw(sample(), effective=5)
            first = screen.window.erases
            screen.draw(sample(), effective=5)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(screen.window.erases, first + 1)
        self.assertEqual(screen.window.refreshes, 2)
        text = "\n".join(v for _, _, v in screen.window.writes)
        self.assertIn("TCP:8080", text)
        self.assertIn("TCP:8085", text)  # idle ports visible by default
        self.assertIn("550.0", text)
        self.assertIn("10m AVG", text)

    def test_all_detected_ports_are_visible_until_user_hides_idle(self):
        screen = self.make_view([ord("a"), ord("q")])
        screen.draw(sample())
        before = "\n".join(v for _, _, v in screen.window.writes)
        self.assertIn("8085", before)
        screen.wait(5)
        after = "\n".join(v for _, _, v in screen.window.writes)
        self.assertNotIn("8085", after)
        self.assertEqual(screen.window.refreshes, 2)

    def test_partial_history_is_not_claimed_as_complete_24h(self):
        self.assertEqual(live_screen.LiveScreen._metric(100.0, 10, 86400), "100.0*")
        self.assertEqual(live_screen.LiveScreen._metric(100.0, 86400, 86400), " 100.0")
        self.assertEqual(live_screen.LiveScreen._metric(None, 0, 86400), "    --")

    def test_keyboard_quits_without_waiting_full_refresh(self):
        screen = self.make_view([ord("q")])
        screen.draw(sample())
        self.assertEqual(screen.wait(60), "select")

    def test_refresh_and_scroll_keys(self):
        screen = self.make_view([ord("+"), ord("-"), FakeCurses.KEY_DOWN,
                                 FakeCurses.KEY_UP, ord("q")])
        screen.draw(sample())
        self.assertEqual(screen.wait(1), "refresh")
        self.assertEqual(screen.requested, 4)
        self.assertEqual(screen.wait(1), "refresh")
        self.assertEqual(screen.requested, 5)
        self.assertEqual(screen.wait(1), "select")


    def test_arrows_select_visible_port_and_q_confirms(self):
        screen = self.make_view([FakeCurses.KEY_DOWN, ord("q")])
        screen.draw(sample())
        self.assertEqual(screen.wait(1), "select")
        row, interface = screen.selection()
        self.assertEqual(row["listen_port"], 22)
        self.assertEqual(interface, "eth0")
        display = "\\n".join(value for _, _, value in screen.window.writes)
        self.assertIn("TCP:22", display)
        self.assertIn("▶", display)

    def test_tab_switches_nic_without_changing_port(self):
        screen = self.make_view([9, 9, ord("q")])
        data = sample()
        data["interfaces"].append({"interface": "wgcf", "rx_mbps": 50,
                                   "tx_mbps": 60})
        screen.draw(data)
        self.assertEqual(screen.wait(1), "select")
        row, interface = screen.selection()
        self.assertEqual(row["listen_port"], 8080)
        self.assertEqual(interface, "wgcf")
        display = "\\n".join(value for _, _, value in screen.window.writes)
        self.assertIn("wgcf", display)

    def test_global_limit_shortcut_selects_current_nic(self):
        screen = self.make_view([9, 9, ord("g")])
        data = sample()
        data["interfaces"].append({"interface": "ens18", "rx_mbps": 1,
                                   "tx_mbps": 2})
        screen.draw(data)
        self.assertEqual(screen.wait(1), "global")
        row, interface = screen.selection(whole_interface=True)
        self.assertIsNone(row)
        self.assertEqual(interface, "ens18")

    def test_default_24_row_terminal_keeps_four_ports_visible(self):
        screen = self.make_view()
        data = sample()
        screen.draw(data)
        ports = [v for _,_,v in screen.window.writes if v.startswith("TCP:")]
        self.assertEqual(ports, ["TCP:8080", "TCP:22",
                                 "TCP:8085", "TCP:8086"])
        self.assertGreaterEqual(screen.page_size, 4)
        self.assertTrue(any("page 1/1" in v.lower()
                            for _,_,v in screen.window.writes))

    def test_four_periods_show_real_volume_beneath_average(self):
        screen = self.make_view()
        screen.window.getmaxyx = lambda: (65, 162)
        data = sample()
        data["rows"][0]["volumes"] = {
            period: {"bytes": 2_000_000_000, "possible_bytes": 2_100_000_000,
                     "coverage_seconds": 600, "requested_seconds": seconds}
            for period, seconds in [("10m",600), ("1h",3600),
                                    ("8h",28800), ("24h",86400)]}
        screen.draw(data)
        displayed = screen.window.writes
        self.assertEqual(screen.row_height, 2)
        text = "\n".join(v for _, _, v in displayed)
        self.assertIn("10m AVG", text)
        self.assertIn("10m 175.0*", text)
        self.assertIn("1h 175.0*", text)
        self.assertIn("8h 175.0*", text)
        self.assertIn("24h 175.0*", text)
        self.assertIn("24h recorded 2.00 GB*", text)
        self.assertEqual(screen._volume_metric(None), "   -- GB")
        exact = {"bytes": 1_000_000_000, "possible_bytes": 1_000_000_000,
                 "coverage_seconds": 600, "requested_seconds": 600}
        self.assertNotIn("*", screen._volume_metric(exact))
        tiny = dict(exact, bytes=1_000_000, possible_bytes=1_000_000)
        self.assertIn("<0.01 GB", screen._volume_metric(tiny))

    def test_fifteen_port_pages_and_next_previous_controls(self):
        screen = self.make_view([ord("n"), ord("p")])
        screen.window.getmaxyx = lambda: (78, 162)
        data = sample()
        data["rows"] = [dict(data["rows"][0], listen_port=3000+i)
                        for i in range(40)]
        screen.draw(data)
        self.assertEqual(screen.page_size, 15)
        self.assertEqual(screen.row_height, 3)
        self.assertTrue(any("page 1/3" in v.lower()
                            for _,_,v in screen.window.writes))
        self.assertIn("TCP:3000", [v for _,_,v in screen.window.writes])
        self.assertNotIn("TCP:3015", [v for _,_,v in screen.window.writes])
        # Trigger page movement using the same key dispatch as the real UI.
        screen._page_move(1)
        self.assertEqual(screen.selected_index, 15)
        self.assertTrue(any("page 2/3" in v.lower()
                            for _,_,v in screen.window.writes))
        self.assertIn("TCP:3015", [v for _,_,v in screen.window.writes])
        screen._page_move(1)
        self.assertEqual(screen.selected_index, 30)
        self.assertIn("TCP:3039", [v for _,_,v in screen.window.writes])
        screen._page_move(-1)
        self.assertEqual(screen.selected_index, 15)

    def test_short_terminal_adapts_page_length_without_cutting_footer(self):
        screen = self.make_view()
        screen.window.getmaxyx = lambda: (29, 118)
        data = sample()
        data["rows"] = [dict(data["rows"][0], listen_port=4000+i)
                        for i in range(35)]
        screen.draw(data)
        self.assertLess(screen.page_size, 15)
        self.assertGreaterEqual(screen.page_size, 1)
        self.assertTrue(any(y == 27 and "↑↓ port" in v
                            for y,x,v in screen.window.writes))
        self.assertTrue(any(y == 28 and "ports" in v
                            for y,x,v in screen.window.writes))

    def test_limit_column_and_large_detail_graph(self):
        view = self.make_view()
        view.window.getmaxyx = lambda: (42, 160)
        data = sample()
        data["speed_limits"] = [{
            "id": "port8080", "port": 8080, "protocol": "tcp",
            "interface": "eth0", "download_mbps": 20, "upload_mbps": 30,
            "enabled": True, "scheduled_now": True,
            "start": "18:00", "end": "02:00",
            "days": list(range(7)), "timezone": "Asia/Tehran"}]
        view.draw(data)
        cells = view.window.writes
        text = "\n".join(v for _, _, v in cells)
        self.assertIn("LIMIT", text)
        self.assertIn("LAST 60s", text)
        self.assertIn("↓20 ↑30 18:00", text)
        self.assertIn("TCP:8080", text)
        self.assertIn("Asia/Tehran", text)
        large = [v for _, _, v in cells if v.startswith("▲ UP   ")]
        self.assertEqual(len(large), 1)
        self.assertGreater(len(large[0]), 90)
        self.assertTrue(any(v.startswith("▼ DOWN ") for _, _, v in cells))

    def test_highlight_is_cyan_bold_without_background(self):
        view = self.make_view([FakeCurses.KEY_DOWN, ord("q")])
        view.draw(sample())
        view.wait(1)
        selected = [(y, x, v) for y, x, v in view.window.writes
                    if v == "TCP:22"]
        self.assertEqual(len(selected), 1)
        # The marker tracks selection and the background is never filled.
        self.assertTrue(any(y == selected[0][0] and v == "▶"
                            for y, _, v in view.window.writes))

    def test_limits_show_future_and_disabled_distinct_from_current(self):
        view = self.make_view()
        data = sample()
        data["speed_limits"] = [
            {"id": "future", "port": 8080, "protocol": "tcp",
             "interface": "eth0", "download_mbps": 20,
             "upload_mbps": 20, "enabled": True,
             "scheduled_now": False, "start": "18:00", "end": "02:00",
             "days": list(range(7)), "timezone": "UTC"},
            {"id": "off", "port": 22, "protocol": "tcp",
             "interface": "eth0", "download_mbps": 7,
             "upload_mbps": 8, "enabled": False,
             "scheduled_now": False, "start": "00:00", "end": "00:00",
             "days": list(range(7)), "timezone": "UTC"}]
        view.draw(data)
        content = "\n".join(v for _, _, v in view.window.writes)
        self.assertIn("↓20 ↑20 18:00", content)
        self.assertIn("↓7 ↑8 OFF", content)
        self.assertEqual(view._limit_for(data["rows"][0], "ALL")["scheduled_now"], False)
        self.assertEqual(view._limit_for(data["rows"][1], "ALL")["enabled"], False)

    def test_nic_global_policy_is_not_falsely_attributed_in_all_view(self):
        view = self.make_view()
        data = sample()
        data["speed_limits"] = [
            {"id": "global", "port": 0, "protocol": "tcp,udp",
             "interface": "eth0", "download_mbps": 50,
             "upload_mbps": 50, "enabled": True,
             "scheduled_now": True, "start": "00:00", "end": "00:00",
             "days": list(range(7)), "timezone": "UTC"}]
        view.draw(data)
        self.assertIsNone(view._limit_for(data["rows"][0], "ALL"))
        nic_info = view._limit_for(data["rows"][0], "eth0")
        self.assertIn("NIC", nic_info["compact"])
        self.assertTrue(nic_info["scheduled_now"])

    def test_one_minute_network_and_port_trends_are_consistent(self):
        screen = self.make_view()
        data = sample()
        data["interface_overview"] = {
            "interface": "ALL", "rx_mbps": 550.0, "tx_mbps": 490.0,
            "graph_60s_rx": "   ▁▅█", "graph_60s_tx": "   ▁▄█",
            "avg1m_rx_mbps": 110, "avg1m_tx_mbps": 90,
            "coverage_1m_seconds": 20}
        data["rows"][0].update({"graph_60s_up": "   ▁▅█",
                                 "graph_60s_down": "   ▁▃█"})
        screen.window.getmaxyx = lambda: (42, 160)
        screen.draw(data)
        cells = screen.window.writes
        text = "\n".join(value for _, _, value in cells)
        self.assertIn("1m avg  110.00* Mbit/s", text)
        self.assertIn("1m avg  90.00* Mbit/s", text)
        self.assertIn("LAST 60s", text)
        self.assertTrue(any(value.startswith("▲ UP   ") for _, _, value in cells))
        self.assertTrue(any(value.startswith("▼ DOWN ") for _, _, value in cells))

    def test_hero_graph_is_multirow_and_preserves_missing_left_edge(self):
        graph = live_screen.LiveScreen._area_graph("   ▁▃█", 24, rows=3)
        self.assertEqual(len(graph), 3)
        self.assertTrue(all(len(line) == 24 for line in graph))
        self.assertTrue(all(line.startswith("      ") for line in graph))
        self.assertIn("█", graph[-1])
        self.assertIn("█", graph[0])

    def test_compact_port_table_does_not_repeat_four_history_periods(self):
        view = self.make_view()
        view.window.getmaxyx = lambda: (24, 118)
        view.draw(sample())
        header = "\n".join(v for y, _, v in view.window.writes if y == 11)
        self.assertIn("DOWN Mb/s", header)
        self.assertIn("UP Mb/s", header)
        self.assertIn("10m AVG", header)
        self.assertIn("1h AVG", header)
        self.assertNotIn("8 hours", header)
        self.assertNotIn("24 hours", header)

    def test_graph_scaling_preserves_missing_history(self):
        trend = live_screen.LiveScreen._large_trend("  ▁▃█", 50)
        self.assertEqual(len(trend), 50)
        self.assertTrue(trend.startswith("    "))
        self.assertTrue(trend.endswith("████"))
        self.assertEqual(live_screen.LiveScreen._large_trend("", 10), "──────────")

    def test_small_terminal_still_keeps_port_rows_and_limits(self):
        view = self.make_view()
        view.window.getmaxyx = lambda: (19, 82)
        data = sample()
        view.draw(data)
        content = "\n".join(v for _, _, v in view.window.writes)
        self.assertIn("TCP:8080", content)
        self.assertIn("LIMIT", content)

    def test_escape_exits_without_setting_limit(self):
        screen = self.make_view([27])
        screen.draw(sample())
        self.assertEqual(screen.wait(1), "quit")


if __name__ == "__main__":
    unittest.main()
