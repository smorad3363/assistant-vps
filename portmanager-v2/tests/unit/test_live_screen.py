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
        self.assertNotIn("TCP:8085", text)
        self.assertIn("550.0", text)
        self.assertIn("10 min", text)

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

    def test_escape_exits_without_setting_limit(self):
        screen = self.make_view([27])
        screen.draw(sample())
        self.assertEqual(screen.wait(1), "quit")


if __name__ == "__main__":
    unittest.main()
