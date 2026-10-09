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
        self.selected_index = 0
        self.interface_name = None
        self.last = None
        self.effective = refresh
        self._totals = {}  # per-interface peak, sample mean and session byte estimate
        self._last_tick = None

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
    def _metric(value, coverage, period_seconds):
        if value is None or not coverage:
            return "    --"
        # Never present a few seconds of traffic as a fully observed 24h
        # average. Mark incomplete windows with '*' in the compact table.
        return (f"{value:5.1f}*" if coverage < period_seconds
                else f"{value:6.1f}")

    def _candidate_rows(self):
        rows = list(self.last.get("rows", [])) if self.last else []
        if self.show_idle:
            return rows
        return [r for r in rows
                if (r.get("now_up_mbps", 0) + r.get("now_down_mbps", 0) >= 0.05
                    or (r.get("avg10m_up_mbps") or 0)
                    + (r.get("avg10m_down_mbps") or 0) >= 0.05)]

    @staticmethod
    def untracked_rates(interface, rows):
        """Directional leftover estimate, NOT an exact conntrack allocation.

        Overlapping NAT chains and interface bridges can make port sums
        incomparable with physical NIC counters. Always label it estimated.
        """
        down = sum(max(0.0, r.get("now_down_mbps", 0) or 0) for r in rows)
        up = sum(max(0.0, r.get("now_up_mbps", 0) or 0) for r in rows)
        return (max(0.0, interface.get("rx_mbps", 0) - down),
                max(0.0, interface.get("tx_mbps", 0) - up))

    def _interfaces(self):
        return list(self.last.get("interfaces", [])) if self.last else []

    def _selected_interface(self):
        links = self._interfaces()
        if not links:
            return {"interface": "loading", "rx_mbps": 0, "tx_mbps": 0}
        if self.interface_name is None or not any(
                link["interface"] == self.interface_name for link in links):
            self.interface_name = links[0]["interface"]
        return next(link for link in links
                    if link["interface"] == self.interface_name)

    def _cycle_interface(self, delta=1):
        links = self._interfaces()
        if not links:
            return
        names = [link["interface"] for link in links]
        current = self._selected_interface()["interface"]
        self.interface_name = names[(names.index(current) + delta) % len(names)]

    def _selected_row(self):
        rows = self._candidate_rows()
        if not rows:
            return None
        self.selected_index = max(0, min(self.selected_index, len(rows) - 1))
        return rows[self.selected_index]

    def selection(self, whole_interface=False):
        """Selected port and NIC; returning data never changes firewall rules."""
        interface = self._selected_interface()["interface"]
        if whole_interface:
            return None, interface
        return self._selected_row(), interface

    def _update_totals(self, data):
        now = time.monotonic()
        dt = min(60.0, max(0.0, now - self._last_tick)) if self._last_tick else 0.0
        self._last_tick = now
        for link in data.get("interfaces", []):
            name = link["interface"]
            value = self._totals.setdefault(name, {
                "count": 0, "rx_sum": 0, "tx_sum": 0,
                "rx_peak": 0, "tx_peak": 0,
                "rx_bytes": 0.0, "tx_bytes": 0.0})
            rx, tx = link["rx_mbps"], link["tx_mbps"]
            value["count"] += 1
            value["rx_sum"] += rx
            value["tx_sum"] += tx
            value["rx_peak"] = max(value["rx_peak"], rx)
            value["tx_peak"] = max(value["tx_peak"], tx)
            value["rx_bytes"] += rx * 1e6 / 8 * dt
            value["tx_bytes"] += tx * 1e6 / 8 * dt

    def _panel(self, x, y, width, title, direction, item, interface):
        if width < 27:
            return
        border = "─" * (width - 2)
        self._write(y, x, "╭" + border + "╮", 1 if direction == "rx" else 2)
        self._write(y + 1, x, "│" + " " * (width - 2) + "│", 1)
        self._write(y + 2, x, "│" + " " * (width - 2) + "│", 1)
        self._write(y + 3, x, "│" + " " * (width - 2) + "│", 1)
        self._write(y + 4, x, "╰" + border + "╯", 1 if direction == "rx" else 2)
        color = 1 if direction == "rx" else 2
        rate = interface.get("rx_mbps", 0) if direction == "rx" else interface.get("tx_mbps", 0)
        self._write(y + 1, x + 2, f"{title}  ({interface.get('interface', '')})", color, True)
        self._write(y + 2, x + 2, f"{rate:,.1f} Mbps", color, True)
        if item:
            avg = item[direction + "_sum"] / max(1, item["count"])
            total_gb = item[direction + "_bytes"] / 1e9
            self._write(y + 3, x + 2,
                        f"Peak {item[direction + '_peak']:.0f}  Avg {avg:.0f}  Session {total_gb:.2f} GB~", 3)

    def draw(self, data=None, effective=None):
        if data is not None:
            self.last = data
            self._update_totals(data)
        if effective is not None:
            self.effective = effective
        if self.window is None:
            return
        self.window.erase()
        height, width = self.window.getmaxyx()
        if height < 19 or width < 68:
            self._write(0, 1, "PORT MANAGER | LIVE", 1, True)
            self._write(2, 1, "Enlarge terminal (min 68 columns x 13 rows).")
            self._write(4, 1, "q / Esc: return", 3)
            self.window.refresh()
            return
        line = "─" * (width - 3)
        self._write(0, 1, " PORT MANAGER  │  ● LIVE ", 1, True)
        self._write(0, max(27, width - 35),
                    f"Refresh: {self.effective:g}s  (set {self.requested}s)", 3)
        self._write(1, 1, line, 1)
        links = self._interfaces()
        interface = self._selected_interface()
        card_width = max(31, (width - 5) // 2)
        stats = self._totals.get(interface["interface"])
        self._panel(1, 2, card_width, "▼ DOWNLOAD", "rx", stats, interface)
        self._panel(card_width + 2, 2, card_width, "▲ UPLOAD", "tx", stats, interface)
        if links:
            pos = next(i for i, link in enumerate(links)
                       if link["interface"] == interface["interface"]) + 1
            self._write(6, 2, f"Interface {pos}/{len(links)}: {interface['interface']}  |  Tab/←→ switch", 1)
        self._write(7, 1, "╭" + "─" * (width - 3) + "╮", 1)
        self._write(8, 2, "PORT TRAFFIC    ↓ ranked by 10m average", 1, True)
        self._write(9, 2, "PORT", 1, True)
        self._write(9, 17, "NOW Mb/s", 1, True)
        self._write(9, 30, "10 min", 1, True)
        self._write(9, 41, "1 hour", 1, True)
        self._write(9, 52, "8 hours", 1, True)
        if width >= 88:
            self._write(9, 63, "24 hours", 1, True)
            self._write(9, 77, "TREND", 1, True)
        self._write(10, 2, "─" * (width - 5), 1)
        rows = self._candidate_rows()
        # Reserve two rows for untracked estimate and one for panel frame.
        max_visible = max(1, height - (23 if height >= 27 else 17))
        self.selected_index = max(0, min(self.selected_index, max(0, len(rows) - 1)))
        self.offset = min(self.offset, max(0, len(rows) - max_visible))
        if self.selected_index < self.offset:
            self.offset = self.selected_index
        elif self.selected_index >= self.offset + max_visible:
            self.offset = self.selected_index - max_visible + 1
        visible = rows[self.offset:self.offset + max_visible]
        for i, row in enumerate(visible):
            y = 11 + i
            port = row.get("listen_port")
            p = str(port) if port else "ALL"
            proto = row.get("protocol", "").upper()
            total = (row.get("now_up_mbps", 0) or 0) + (row.get("now_down_mbps", 0) or 0)
            chosen = self.offset + i == self.selected_index
            self._write(y, 1, "▶" if chosen else " ", 1, chosen)
            self._write(y, 3, f"{proto}:{p}", 2 if chosen else 0, chosen)
            self._write(y, 17, f"{total:8.1f}", 2 if total >= .05 else 0)
            stats_ = row.get("averages", {})
            for key, pos in (("10m", 30), ("1h", 41), ("8h", 52), ("24h", 63)):
                if key == "24h" and width < 88:
                    continue
                avg = stats_.get(key, {})
                up, down = avg.get("up_mbps"), avg.get("down_mbps")
                number = up + down if up is not None and down is not None else None
                self._write(y, pos, self._metric(
                    number, avg.get("coverage_seconds", 0),
                    avg.get("requested_seconds",
                            {"10m": 600, "1h": 3600, "8h": 28800, "24h": 86400}[key])))
            if width >= 88:
                trend = str(row.get("graph_up", "")).strip()[-max(3, width - 81):]
                self._write(y, 77, trend, 2)
        if not rows:
            self._write(11, 3, "Waiting for tracked port samples. NIC totals above are live.", 3)
        # Interface summary is independent of per-port attribution.
        # A NIC switch changes the cards and the chosen interface for a cap.
        summary_y = 13 + len(visible)
        if links and height >= 27 and summary_y + 2 < height - 6:
            self._write(summary_y, 2, "NETWORK INTERFACES  (Tab/←→ to choose)", 1, True)
            current_pos = next(i for i, link in enumerate(links)
                               if link["interface"] == interface["interface"])
            slots = max(1, min(8, height - 8 - summary_y))
            start = min(max(0, current_pos - slots + 1), max(0, len(links) - slots))
            for i, link in enumerate(links[start:start + slots]):
                active = link["interface"] == interface["interface"]
                self._write(summary_y + 1 + i, 2,
                            f"{'▶' if active else ' '} {link['interface']:<16}"
                            f"  ↓ {link['rx_mbps']:>9.1f}  ↑ {link['tx_mbps']:>9.1f} Mb/s",
                            2 if active else 0, active)
            if len(links) > slots:
                self._write(summary_y, 47,
                            f"Showing {start + 1}-{min(len(links), start + slots)}/{len(links)}", 3)
        # We cannot prove the precise destination port of untracked flows.
        # Display the difference as a directional estimate, not as a rule.
        if self.last and links:
            down, up = self.untracked_rates(interface, self.last.get("rows", []))
            if down + up >= .1:
                self._write(height - 5, 2, f"OTHER / UNKNOWN ~  ↓ {down:,.1f}  ↑ {up:,.1f} Mbps", 3, True)
        self._write(height - 4, 2,
                    "* incomplete period  |  ~ estimated  |  averages in Mb/s (not GB)", 3)
        self._write(height - 3, 1, "╰" + line + "╯", 1)
        self._write(height - 2, 2, "↑↓ choose port | Enter/q limit | g entire NIC | Tab/←→ NIC | a idle | +/- rate | Esc back")
        state = "History ON (background)" if self.last and self.last.get("background_history_active") else "History: viewer only"
        self._write(height - 1, 2,
                    f"{len(rows)} ports  •  {interface['interface']}  •  {state}  •  Ctrl+C back", 1)
        self.window.refresh()

    def wait(self, interval):
        """Poll keyboard promptly; arrows select a port, Tab switches NIC."""
        deadline = time.monotonic() + interval
        while time.monotonic() < deadline:
            key = self.window.getch()
            if key in (10, 13, getattr(self.curses, "KEY_ENTER", 343),
                       ord("q"), ord("Q")):
                if self._selected_row() is not None:
                    return "select"
                if key in (ord("q"), ord("Q")):
                    return "quit"
            elif key in (27, ord("s"), ord("S")):
                return "quit"
            elif key in (ord("g"), ord("G")):
                return "global" if self._interfaces() else "quit"
            elif key in (9, getattr(self.curses, "KEY_RIGHT", 261)):
                self._cycle_interface(1)
                self.draw()
            elif key in (getattr(self.curses, "KEY_BTAB", 353),
                         getattr(self.curses, "KEY_LEFT", 260)):
                self._cycle_interface(-1)
                self.draw()
            elif key in (ord("a"), ord("A")):
                self.show_idle = not self.show_idle
                self.selected_index = 0
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
                self.selected_index = min(
                    max(0, len(self._candidate_rows()) - 1),
                    self.selected_index + 1)
                self.draw()
            elif key in (self.curses.KEY_UP, ord("k")):
                self.selected_index = max(0, self.selected_index - 1)
                self.draw()
            elif key == self.curses.KEY_RESIZE:
                self.draw()
        return "tick"
