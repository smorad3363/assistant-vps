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

    def test_idle_ports_are_hidden_until_a_toggle(self):
        screen = self.make_view([ord("a"), ord("q")])
        screen.draw(sample())
        before = "\n".join(v for _, _, v in screen.window.writes)
        self.assertNotIn("8085", before)
        screen.wait(5)
        after = "\n".join(v for _, _, v in screen.window.writes)
        self.assertIn("8085", after)
        self.assertEqual(screen.window.refreshes, 2)

    def test_keyboard_quits_without_waiting_full_refresh(self):
        screen = self.make_view([ord("q")])
        screen.draw(sample())
        self.assertEqual(screen.wait(60), "quit")

    def test_refresh_and_scroll_keys(self):
        screen = self.make_view([ord("+"), ord("-"), FakeCurses.KEY_DOWN,
                                 FakeCurses.KEY_UP, ord("q")])
        screen.draw(sample())
        self.assertEqual(screen.wait(1), "refresh")
        self.assertEqual(screen.requested, 4)
        self.assertEqual(screen.wait(1), "refresh")
        self.assertEqual(screen.requested, 5)
        self.assertEqual(screen.wait(1), "quit")


if __name__ == "__main__":
    unittest.main()
