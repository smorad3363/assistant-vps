"""Fixed-screen, responsive terminal monitor for Debian/Ubuntu.

Unlike repeated ANSI print(), curses owns an alternate terminal screen,
updates rows in-place, handles resize and keyboard input, then restores the
caller's menu. JSON and --once modes never enter curses.
"""
import os
import sys
import time

from .errors import PM2Error
from .graph_style import avg_text, rate_text


class LiveScreen:
    def __init__(self, refresh):
        self.requested = refresh
        self.window = None
        self.curses = None
        self.show_idle = True  # default shows every discovered port
        self.offset = 0
        self.selected_index = 0
        self.interface_name = "ALL"  # default keeps the full interface overview
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
        names = [x["interface"] for x in links]
        if self.interface_name not in names and self.interface_name != "ALL":
            self.interface_name = "ALL"
        if self.interface_name == "ALL":
            # Useful overview, not physical host bandwidth: bridges, veth
            # and tunnels may count the same packet multiple times.
            return (self.last.get("interface_overview") if self.last and
                    self.last.get("interface_overview") else
                    {"interface": "ALL", "rx_mbps": sum(x["rx_mbps"] for x in links),
                     "tx_mbps": sum(x["tx_mbps"] for x in links)})
        return next(x for x in links if x["interface"] == self.interface_name)

    def _cycle_interface(self, delta=1):
        links = self._interfaces()
        if not links:
            return
        names = ["ALL"] + [link["interface"] for link in links]
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
        if interface == "ALL" and len(self._interfaces()) == 1:
            interface = self._interfaces()[0]["interface"]
        if whole_interface:
            return None, interface
        return self._selected_row(), interface

    def _update_totals(self, data):
        now = time.monotonic()
        dt = min(60.0, max(0.0, now - self._last_tick)) if self._last_tick else 0.0
        self._last_tick = now
        links = data.get("interfaces", [])
        overview = {"interface": "ALL", "rx_mbps": sum(x["rx_mbps"] for x in links),
                    "tx_mbps": sum(x["tx_mbps"] for x in links)}
        for link in ([overview] + links if links else []):
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

    @staticmethod
    def _area_graph(value, columns, rows=3):
        """Turn a one-line sparkline into a compact filled terminal area chart."""
        columns = max(1, min(int(columns), 160))
        rows = max(1, min(int(rows), 5))
        scaled = LiveScreen._large_trend(value, columns)
        levels = {char: index for index, char in enumerate(" ▁▂▃▄▅▆▇█")}
        output = []
        for visual_row in range(rows):
            threshold = rows - visual_row
            line = []
            for char in scaled:
                if char == " ":
                    line.append(" ")
                    continue
                level = levels.get(char, 0) / 8 * rows
                if level >= threshold:
                    line.append("█")
                elif level > threshold - 1:
                    line.append("▄")
                else:
                    line.append(" ")
            output.append("".join(line))
        return output

    def _panel(self, x, y, width, title, direction, item, interface):
        """Seven-row hero card: current rate, 1m mean and a real 3-row trace."""
        if width < 27:
            return
        color = 2 if direction == "rx" else 3  # RX green / TX yellow
        border = "─" * (width - 2)
        self._write(y, x, "╭" + border + "╮", 1)
        for row in range(1, 6):
            self._write(y + row, x, "│" + " " * (width - 2) + "│", 1)
        self._write(y + 6, x, "╰" + border + "╯", 1)
        rate = (interface.get("rx_mbps", 0) if direction == "rx"
                else interface.get("tx_mbps", 0))
        average = interface.get("avg1m_" + direction + "_mbps")
        coverage = interface.get("coverage_1m_seconds", 0)
        self._write(y + 1, x + 2, title, color, True)
        self._write(y + 1, max(x + 15, x + width - 22),
                    rate_text(rate), color, True)
        self._write(y + 2, x + 2,
                    f"1m avg  {avg_text(average, coverage)} Mbit/s"
                    if average is not None else "1m avg  --", 0)
        graph = interface.get("graph_60s_" + direction)
        if graph:
            for offset, line in enumerate(
                    self._area_graph(graph, width - 4, rows=3)):
                self._write(y + 3 + offset, x + 2, line, color)
        elif item:
            avg = item[direction + "_sum"] / max(1, item["count"])
            total_gb = item[direction + "_bytes"] / 1e9
            self._write(y + 3, x + 2,
                        f"Peak {item[direction + '_peak']:.1f} Mbit/s", color)
            self._write(y + 4, x + 2, f"Session avg {avg:.1f} Mbit/s", 0)
            self._write(y + 5, x + 2, f"Session ~{total_gb:.2f} GB", 0)

    @staticmethod
    def _large_trend(value, columns):
        """Scale sampled bars horizontally; blanks remain missing history."""
        raw = str(value or "").rstrip("\n")
        columns = max(0, min(int(columns), 160))
        if not raw or not columns:
            return "─" * columns
        if len(raw) == columns:
            return raw
        return "".join(raw[min(len(raw) - 1, i * len(raw) // columns)]
                       for i in range(columns))

    def _limit_for(self, row, nic):
        """Configured policy + schedule match, not an assertion about tc state."""
        port = row.get("listen_port")
        proto = row.get("protocol")
        policies = self.last.get("speed_limits", []) if self.last else []
        matches = [p for p in policies
                   if p.get("port") == port
                   and proto in str(p.get("protocol", "")).split(",")
                   and (nic == "ALL" or p.get("interface") in (None, nic))]
        global_scope = False
        if not matches and nic != "ALL":
            matches = [p for p in policies if p.get("port") == 0
                       and p.get("interface") == nic]
            global_scope = bool(matches)
        if not matches:
            return None
        # Scheduled-now first, then future configured, then disabled.
        matches.sort(key=lambda p: (not p.get("scheduled_now"),
                                    not p.get("enabled"), p.get("id", "")))
        chosen = matches[0]
        active = bool(chosen.get("scheduled_now"))
        enabled = bool(chosen.get("enabled"))
        when = ("OFF" if not enabled else
                "ALL DAY" if chosen.get("start") == chosen.get("end")
                            and len(chosen.get("days", [])) == 7 else
                f'{chosen.get("start", "--")}–{chosen.get("end", "--")}')
        down = chosen.get("download_mbps", 0)
        up = chosen.get("upload_mbps", 0)
        compact = f"↓{down} ↑{up} {when}"
        if global_scope:
            compact = "NIC " + compact
        if len(matches) > 1:
            compact += f" +{len(matches) - 1}"
        detailed = (f"{'NIC-WIDE ' if global_scope else ''}↓{down} / ↑{up} Mbps"
                    f"  |  {when}"
                    f"  |  {chosen.get('interface') or 'auto'}"
                    f"  |  {chosen.get('timezone', 'UTC')}"
                    f"  |  {'window NOW' if active else 'scheduled later' if enabled else 'disabled'}")
        return {"compact": compact, "detail": detailed,
                "scheduled_now": active, "enabled": enabled}

    @staticmethod
    def _volume_metric(item):
        """Recorded integer bytes; never infer GB by multiplying Mbps."""
        if not item or not item.get("coverage_seconds"):
            return "   -- GB"
        raw_bytes = item.get("bytes", 0)
        partial = (item.get("coverage_seconds", 0) <
                   item.get("requested_seconds", float("inf")) or
                   item.get("possible_bytes", 0) > raw_bytes)
        # An actual few megabytes must never look like zero billed traffic.
        value = "<0.01" if 0 < raw_bytes < 10_000_000 else f"{raw_bytes/1e9:.2f}"
        return f"{value:>6} GB{'*' if partial else ' '}"

    def _page_move(self, direction):
        rows = self._candidate_rows()
        if not rows:
            return
        size = max(1, getattr(self, "page_size", 15))
        count = max(1, (len(rows) + size - 1) // size)
        current = self.selected_index // size
        target = max(0, min(count - 1, current + direction))
        self.selected_index = min(len(rows) - 1, target * size)
        self.offset = target * size
        self.draw()

    def draw(self, data=None, effective=None):
        """Responsive btop-style view: big live graph, compact ports, detail on selection."""
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
            self._write(0, 1, "PORT MANAGER  •  LIVE TRAFFIC", 1, True)
            self._write(2, 1, "Enlarge terminal (min 68 columns x 19 rows).", 3)
            self._write(4, 1, "Esc: back", 3)
            self.window.refresh()
            return

        line = "─" * (width - 3)
        self._write(0, 1, " PORT MANAGER  │  ● LIVE TRAFFIC ", 1, True)
        self._write(0, max(35, width - 27),
                    f"{self.effective:g}s refresh", 3)
        self._write(1, 1, line, 1)

        links = self._interfaces()
        interface = self._selected_interface()
        nic = interface["interface"]
        stats = self._totals.get(nic)
        card_width = max(31, (width - 5) // 2)
        self._panel(1, 2, card_width, "▼ DOWNLOAD / RX", "rx", stats, interface)
        self._panel(card_width + 2, 2, card_width,
                    "▲ UPLOAD / TX", "tx", stats, interface)

        names = ["ALL"] + [link["interface"] for link in links]
        if links:
            position = names.index(nic) + 1
            interface_line = f"Network {position}/{len(names)}  {nic}"
            if nic == "ALL":
                interface_line += "  · combined view"
            if self.last and width >= 105:
                unknown_down, unknown_up = self.untracked_rates(
                    interface, self.last.get("rows", []))
                if unknown_down + unknown_up >= .1:
                    interface_line += (f"  · untracked ~ ↓{unknown_down:.1f}"
                                       f" ↑{unknown_up:.1f} Mb/s")
            self._write(9, 2, interface_line, 1 if nic != "ALL" else 3)

        rows = self._candidate_rows()
        detail_height = 6 if height >= 34 else 0
        footer_start = height - 3
        base_y = 13
        available = max(1, footer_start - base_y -
                        (detail_height + 1 if detail_height else 0))
        self.row_height = 2 if available >= 30 and width >= 105 else 1
        self.page_size = max(1, min(15, available // self.row_height))
        pages = max(1, (len(rows) + self.page_size - 1) // self.page_size)
        self.selected_index = max(0, min(self.selected_index,
                                         max(0, len(rows) - 1)))
        page = self.selected_index // self.page_size
        self.offset = page * self.page_size
        visible = rows[self.offset:self.offset + self.page_size]

        self._write(10, 1, "╭─ PORTS " + "─" * max(0, width - 11) + "╮", 1)
        self._write(10, max(28, width - 28),
                    f"{len(rows)} ports  ·  page {page + 1}/{pages}", 3)

        wide = width >= 105
        down_x, up_x = (17, 31)
        avg10_x = 45
        avg1h_x = 57 if wide else None
        limit_x = 69 if wide else 57
        trend_x = 96 if width >= 125 else None
        self._write(11, 3, "PORT", 1, True)
        self._write(11, down_x, "↓ DOWN Mb/s", 2, True)
        self._write(11, up_x, "↑ UP Mb/s", 3, True)
        self._write(11, avg10_x, "10m AVG", 1, True)
        if avg1h_x is not None:
            self._write(11, avg1h_x, "1h AVG", 1, True)
        self._write(11, limit_x, "LIMIT", 1, True)
        if trend_x is not None:
            self._write(11, trend_x, "LAST 60s", 1, True)
        self._write(12, 2, "─" * (width - 5), 1)

        for i, row in enumerate(visible):
            y = base_y + i * self.row_height
            port = row.get("listen_port")
            label = f'{str(row.get("protocol", "")).upper()}:{port if port else "ALL"}'
            down = row.get("now_down_mbps", 0) or 0
            up = row.get("now_up_mbps", 0) or 0
            selected = self.offset + i == self.selected_index
            self._write(y, 1, "▶" if selected else " ", 1, selected)
            self._write(y, 3, label[:13], 1 if selected else 0, selected)
            self._write(y, down_x, f"{down:10.1f}", 2 if down >= .05 else 0, selected)
            self._write(y, up_x, f"{up:9.1f}", 3 if up >= .05 else 0, selected)

            averages = row.get("averages", {})
            ten = averages.get("10m", {})
            ten_value = ((ten.get("up_mbps") or 0) + (ten.get("down_mbps") or 0)
                         if ten.get("coverage_seconds") else None)
            self._write(y, avg10_x, self._metric(
                ten_value, ten.get("coverage_seconds", 0), 600), 0, selected)
            if avg1h_x is not None:
                hour = averages.get("1h", {})
                hour_value = ((hour.get("up_mbps") or 0) +
                              (hour.get("down_mbps") or 0)
                              if hour.get("coverage_seconds") else None)
                self._write(y, avg1h_x, self._metric(
                    hour_value, hour.get("coverage_seconds", 0), 3600), 0, selected)

            limit_info = self._limit_for(row, nic)
            limit_text = limit_info["compact"] if limit_info else "—"
            limit_width = max(6, (trend_x or width - 1) - limit_x - 2)
            self._write(y, limit_x, limit_text[:limit_width],
                        2 if limit_info and limit_info["scheduled_now"] else
                        3 if limit_info and limit_info["enabled"] else 0,
                        selected)
            if trend_x is not None:
                trend = (row.get("graph_60s_down") or
                         row.get("graph_60s_up") or row.get("graph_down", ""))
                self._write(y, trend_x,
                            self._large_trend(trend, width - trend_x - 2),
                            2, selected)
            if self.row_height == 2:
                name = str(row.get("name") or "")
                self._write(y + 1, 5, name[:max(0, down_x - 7)], 0, selected)

        if not rows:
            self._write(base_y, 3, "Waiting for port traffic samples…", 3)

        panel_y = base_y + len(visible) * self.row_height
        selected_row = self._selected_row()
        if (selected_row is not None and detail_height and
                panel_y + detail_height < footer_start):
            y = panel_y + 1
            proto = selected_row.get("protocol", "").upper()
            port = selected_row.get("listen_port") or "ALL"
            name = str(selected_row.get("name") or "")
            self._write(y, 2, "╭─ " + f"{proto}:{port}  {name}"[:width - 10] +
                        " " + "─" * max(0, width - 12 - len(f"{proto}:{port}  {name}")),
                        1, True)
            metrics = []
            for period, seconds in (("10m", 600), ("1h", 3600),
                                    ("8h", 28800), ("24h", 86400)):
                stat = selected_row.get("averages", {}).get(period, {})
                if stat.get("coverage_seconds"):
                    value = (stat.get("up_mbps") or 0) + (stat.get("down_mbps") or 0)
                    metrics.append(f"{period} {value:.1f}{'*' if stat.get('coverage_seconds', 0) < seconds else ''}")
                else:
                    metrics.append(f"{period} --")
            self._write(y + 1, 4, "AVG Mb/s   " + "   ".join(metrics), 0)

            graph_width = max(8, width - 18)
            up_graph = (selected_row.get("graph_60s_up") or
                        selected_row.get("graph_up", ""))
            down_graph = (selected_row.get("graph_60s_down") or
                          selected_row.get("graph_down", ""))
            self._write(y + 2, 4, "▲ UP   " +
                        self._large_trend(up_graph, graph_width), 3)
            self._write(y + 3, 4, "▼ DOWN " +
                        self._large_trend(down_graph, graph_width), 2)
            lim = self._limit_for(selected_row, nic)
            volume = selected_row.get("volumes", {}).get("24h")
            volume_text = self._volume_metric(volume).strip()
            detail = lim["detail"] if lim else "No speed limit"
            self._write(y + 4, 4,
                        f"24h recorded {volume_text}   ·   {detail}"[:width - 8],
                        2 if lim and lim["scheduled_now"] else 0)
            self._write(y + 5, 2, "╰" + "─" * (width - 4) + "╯", 1)

        self._write(height - 3, 1, "╰" + line + "╯", 1)
        self._write(height - 2, 2,
                    "↑↓ port   ←→ network   Enter limit   A active/all   +/- refresh   Esc back",
                    0)
        state = ("history on" if self.last and
                 self.last.get("background_history_active") else "viewer history")
        self._write(height - 1, 2,
                    f"{nic}  ·  {len(rows)} ports  ·  {state}"
                    + ("  ·  * partial history" if rows else ""), 1)
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
            elif key in (getattr(self.curses, "KEY_NPAGE", 338), ord("n"), ord("N")):
                self._page_move(1)
            elif key in (getattr(self.curses, "KEY_PPAGE", 339), ord("p"), ord("P")):
                self._page_move(-1)
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
