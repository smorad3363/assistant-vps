"""Fixed-screen, responsive terminal monitor for Debian/Ubuntu.

Unlike repeated ANSI print(), curses owns an alternate terminal screen,
updates rows in-place, handles resize and keyboard input, then restores the
caller's menu. JSON and --once modes never enter curses.
"""
import os
import sys
import time

from .errors import PM2Error


class LiveScreen:
    def __init__(self, refresh):
        self.requested = refresh
        self.window = None
        self.curses = None
        self.show_idle = False
        self.offset = 0
        self.last = None
        self.effective = refresh

    def __enter__(self):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise PM2Error("E_VALIDATION",
                           "Full-screen live view needs an interactive TTY. Use --once --json for scripts.")
        if os.environ.get("TERM", "").lower() in ("", "dumb", "unknown"):
            raise PM2Error("E_UNSUPPORTED",
                           "Full-screen view needs a terminal with TERM=xterm-256color or screen-256color.")
        try:
            import curses
            self.curses = curses
            self.window = curses.initscr()
            curses.noecho()
            curses.cbreak()
            self.window.keypad(True)
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            if curses.has_colors() and not os.environ.get("NO_COLOR"):
                curses.start_color()
                try:
                    curses.use_default_colors()
                except curses.error:
                    pass
                curses.init_pair(1, curses.COLOR_CYAN, -1)
                curses.init_pair(2, curses.COLOR_GREEN, -1)
                curses.init_pair(3, curses.COLOR_YELLOW, -1)
            self.window.timeout(100)
            self.draw()
            return self
        except Exception as exc:
            self.__exit__(None, None, None)
            raise PM2Error("E_UNSUPPORTED", "Unable to initialize interactive terminal display",
                           {"error": str(exc)[:120]}) from exc

    def __exit__(self, *_):
        if self.curses is not None:
            try:
                if self.window is not None:
                    self.window.keypad(False)
                self.curses.nocbreak()
                self.curses.echo()
                self.curses.endwin()
            except self.curses.error:
                pass
        self.window = None
        return False

    def _write(self, y, x, value, color=0, bold=False):
        if self.window is None:
            return
        height, width = self.window.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= width - 1:
            return
        text = str(value).replace("\n", " ").replace("\r", "")
        if not text:
            return
        curses = self.curses
        attr = (curses.A_BOLD if bold else 0)
        if color and curses.has_colors() and not os.environ.get("NO_COLOR"):
            attr |= curses.color_pair(color)
        try:
            self.window.addnstr(y, x, text, width - x - 1, attr)
        except curses.error:
            pass  # Rightmost column / very small terminal.

    @staticmethod
    def _metric(value, coverage):
        return f"{value:6.1f}" if value is not None and coverage else "    --"

    def _candidate_rows(self):
        rows = list(self.last.get("rows", [])) if self.last else []
        if self.show_idle:
            return rows
        return [r for r in rows
                if (r.get("now_up_mbps", 0) + r.get("now_down_mbps", 0) >= 0.05
                    or (r.get("avg10m_up_mbps") or 0)
                    + (r.get("avg10m_down_mbps") or 0) >= 0.05)]

    def draw(self, data=None, effective=None):
        if data is not None:
            self.last = data
        if effective is not None:
            self.effective = effective
        if self.window is None:
            return
        self.window.erase()
        height, width = self.window.getmaxyx()
        if height < 11 or width < 58:
            self._write(0, 1, "PORT MANAGER LIVE")
            self._write(2, 1, "Enlarge the terminal (min 58x11).")
            self._write(4, 1, "q / Esc: return  |  Ctrl+C: return")
            self.window.refresh()
            return
        self._write(0, 1, "PORT MANAGER  /  LIVE", 1, True)
        self._write(0, min(28, width - 20),
                    f"Refresh {self.effective:g}s  (set {self.requested}s)", 3)
        links = self.last.get("interfaces", []) if self.last else []
        if links:
            net = links[0]
            self._write(1, 1,
                        f"{net['interface'][:12]:12}   UP {net['tx_mbps']:7.1f}  "
                        f"DOWN {net['rx_mbps']:7.1f} Mbps  [WHOLE INTERFACE]", 2, True)
        else:
            self._write(1, 1, "Collecting network baseline... first sample is not a measurement.", 3)
        self._write(2, 1, "-" * (width - 3), 1)
        self._write(3, 1, "PORT      NOW Mb/s   10 min     1 hour    8 hours  24 hours  TREND", 1, True)
        rows = self._candidate_rows()
        available = max(1, height - 8)
        self.offset = min(self.offset, max(0, len(rows) - available))
        if rows:
            for i, row in enumerate(rows[self.offset:self.offset + available]):
                port = row.get("listen_port") or 0
                proto = row.get("protocol", "").upper()
                stats = row.get("averages", {})
                nums = []
                for period in ("10m", "1h", "8h", "24h"):
                    data_ = stats.get(period, {})
                    up = data_.get("up_mbps")
                    down = data_.get("down_mbps")
                    total = up + down if up is not None and down is not None else None
                    nums.append(self._metric(total, data_.get("coverage_seconds", 0)))
                now = (row.get("now_up_mbps", 0) + row.get("now_down_mbps", 0))
                trend = (row.get("graph_up", "").rstrip() or " ") [-15:]
                line = (f"{proto}:{port:<6} {now:8.1f} " +
                        " ".join(nums) + "  " + trend)
                self._write(4 + i, 1, line, 2 if i == 0 else 0, i == 0)
        else:
            self._write(5, 2, "Waiting for active per-port samples..." if self.last else
                        "Initializing counters (please wait)...", 3)
            self._write(6, 2, "Use 'a' to include idle ports. Network totals above are independent.")
        footer = height - 3
        self._write(footer, 1, "-" * (width - 3), 1)
        if self.last:
            coverage = self.last.get("port_coverage", "configured")
            self._write(footer + 1, 1,
                        f"Visible {min(len(rows), available)} / {len(rows)}    "
                        f"Source: {coverage}    "
                        f"{'Idle included' if self.show_idle else 'Active only'}")
        self._write(height - 1, 1,
                    "q/Esc: choose port   a: idle ports   +/-: refresh   up/down: scroll", 1)
        self.window.refresh()

    def wait(self, interval):
        """Service UI every 100ms, rather than blocking on time.sleep()."""
        deadline = time.monotonic() + interval
        while time.monotonic() < deadline:
            key = self.window.getch()
            if key in (ord("q"), ord("Q"), 27, ord("s"), ord("S")):
                return "quit"
            if key in (ord("a"), ord("A")):
                self.show_idle = not self.show_idle
                self.offset = 0
                self.draw()
            elif key in (ord("+"), ord("=")):
                self.requested = max(2, self.requested - 1)
                self.draw()
                return "refresh"
            elif key in (ord("-"), ord("_")):
                self.requested = min(60, self.requested + 1)
                self.draw()
                return "refresh"
            elif key in (self.curses.KEY_DOWN, ord("j")):
                self.offset += 1
                self.draw()
            elif key in (self.curses.KEY_UP, ord("k")):
                self.offset = max(0, self.offset - 1)
                self.draw()
            elif key == self.curses.KEY_RESIZE:
                self.draw()
        return "tick"
