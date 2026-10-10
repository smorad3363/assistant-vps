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
            return {"interface": "ALL", "rx_mbps": sum(x["rx_mbps"] for x in links),
                    "tx_mbps": sum(x["tx_mbps"] for x in links)}
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

    @staticmethod
    def _large_trend(value, columns):
        """Scale existing 10-minute samples; blanks remain missing history."""
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
        volume = item.get("bytes", 0) / 1e9
        partial = (item.get("coverage_seconds", 0) <
                   item.get("requested_seconds", float("inf")) or
                   item.get("possible_bytes", 0) > item.get("bytes", 0))
        return f"{volume:6.2f} GB{'*' if partial else ' '}"

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
            self._write(2, 1, "Enlarge terminal (min 68 columns x 19 rows).", 3)
            self._write(4, 1, "Esc: back", 3)
            self.window.refresh()
            return
        line = "─" * (width - 3)
        self._write(0, 1, " PORT MANAGER  │  ● LIVE ", 1, True)
        self._write(0, max(27, width - 35),
                    f"Refresh: {self.effective:g}s (set {self.requested}s)", 3)
        self._write(1, 1, line, 1)
        links = self._interfaces()
        interface = self._selected_interface()
        nic = interface["interface"]
        card_width = max(31, (width - 5) // 2)
        stats = self._totals.get(nic)
        self._panel(1, 2, card_width, "▼ DOWNLOAD", "rx", stats, interface)
        self._panel(card_width + 2, 2, card_width, "▲ UPLOAD", "tx", stats, interface)
        if links:
            names = ["ALL"] + [link["interface"] for link in links]
            note = "NICs can overlap" if nic == "ALL" else "one network"
            self._write(6, 2,
                        f"Interface {names.index(nic) + 1}/{len(names)}: {nic} | {note} | Tab/←→ switch",
                        3 if nic == "ALL" else 1)
        self._write(7, 1, "╭" + "─" * (width - 3) + "╮", 1)
        self._write(8, 2, "PORT TRAFFIC  ·  speed + recorded volume  ·  ranked by 10m", 1, True)

        limit_x = 74 if width >= 105 else 70 if width >= 88 else 60
        trend_x = 105 if width >= 150 else 100 if width >= 128 else (
            96 if width >= 112 else None)
        limit_width = max(6, (trend_x - limit_x - 2 if trend_x
                              else width - limit_x - 3))
        periods = (("10m", 29), ("1h", 40), ("8h", 51), ("24h", 62))
        seconds = {"10m": 600, "1h": 3600, "8h": 28800, "24h": 86400}
        self._write(9, 3, "PORT", 1, True)
        self._write(9, 17, "NOW Mb/s", 1, True)
        for name, xpos in periods:
            if name == "24h" and width < 88:
                continue
            self._write(9, xpos, {"10m": "10 min", "1h": "1 hour",
                                   "8h": "8 hours", "24h": "24 hours"}[name], 1, True)
            self._write(10, xpos, "avg / GB", 3)
        self._write(9, limit_x, "LIMIT / HOURS", 1, True)
        if trend_x and width - trend_x > 6:
            self._write(9, trend_x, "TREND", 1, True)
            self._write(10, trend_x, "▲ upload  ▼ download", 3)
        self._write(11, 2, "─" * (width - 5), 1)

        rows = self._candidate_rows()
        detail_height = 5 if height >= 37 else (3 if height >= 27 else 0)
        nic_slots = (min(len(links), 2) if height >= 65 else 0)
        # A short SSH window prioritizes the measured port rows. The
        # untracked-rate footer and secondary panels may be omitted there.
        show_other = height >= 34
        footer_start = height - (5 if show_other else 4)
        reserved = (detail_height + (nic_slots + 2 if nic_slots else 0) + 2
                    if height >= 34 else 0)
        available = max(2, footer_start - 12 - reserved)
        self.row_height = 3 if available >= 45 else 2
        self.page_size = max(1, min(15, available // self.row_height))
        pages = max(1, (len(rows) + self.page_size - 1) // self.page_size)
        self.selected_index = max(0, min(self.selected_index, max(0, len(rows) - 1)))
        page = self.selected_index // self.page_size
        self.offset = page * self.page_size
        self._write(8, max(65, width - 30),
                    f"PAGE {page + 1}/{pages}  ({len(rows)} ports)", 3)
        visible = rows[self.offset:self.offset+self.page_size]

        for i, row in enumerate(visible):
            y = 12 + i * self.row_height
            port = row.get("listen_port")
            name = f'{str(row.get("protocol", "")).upper()}:{port if port else "ALL"}'
            total = (row.get("now_up_mbps", 0) or 0) + (row.get("now_down_mbps", 0) or 0)
            selected = self.offset + i == self.selected_index
            self._write(y, 1, "▶" if selected else " ", 1, selected)
            self._write(y, 3, name[:13], 1 if selected else 0, selected)
            self._write(y, 17, f"{total:8.1f}", 2 if total >= .05 else 0, selected)
            stats_ = row.get("averages", {})
            volumes = row.get("volumes", {})
            for period, xpos in periods:
                if period == "24h" and width < 88:
                    continue
                avg = stats_.get(period, {})
                up, down = avg.get("up_mbps"), avg.get("down_mbps")
                number = up + down if up is not None and down is not None else None
                self._write(y, xpos, self._metric(
                    number, avg.get("coverage_seconds", 0),
                    avg.get("requested_seconds", seconds[period])))
                self._write(y + 1, xpos,
                            self._volume_metric(volumes.get(period)), 3, selected)
            limit_info = self._limit_for(row, nic)
            limit_text = (limit_info["compact"] if limit_info else "—")
            self._write(y, limit_x, limit_text[:limit_width],
                        2 if limit_info and limit_info["scheduled_now"] else
                        3 if limit_info and limit_info["enabled"] else 0,
                        selected)
            if trend_x and width - trend_x > 6:
                length = width - trend_x - 2
                self._write(y, trend_x, self._large_trend(
                    row.get("graph_up", ""), length), 2, selected)
                self._write(y + 1, trend_x, self._large_trend(
                    row.get("graph_down", ""), length), 1, selected)
        if not rows:
            self._write(12, 3, "Waiting for recorded port samples.", 3)

        panel_y = 12 + len(visible) * self.row_height
        selected_row = self._selected_row()
        if selected_row is not None and detail_height and panel_y + detail_height < footer_start:
            proto = selected_row.get("protocol", "").upper()
            port = selected_row.get("listen_port") or "ALL"
            now_rate = ((selected_row.get("now_down_mbps") or 0) +
                        (selected_row.get("now_up_mbps") or 0))
            self._write(panel_y, 2,
                        f"╭─ SELECTED PORT: {proto}:{port}  │  Now: {now_rate:.1f} Mb/s " +
                        "─" * max(0, width - 55), 1, True)
            lim = self._limit_for(selected_row, nic)
            if detail_height == 5:
                detail = lim["detail"] if lim else "No speed limit configured"
                self._write(panel_y + 1, 4, "Limit: " + detail[:width - 14],
                            2 if lim and lim["scheduled_now"] else 3 if lim else 0)
                self._write(panel_y + 2, 4, "▲ UP    " + self._large_trend(
                    selected_row.get("graph_up"), width - 16), 2)
                self._write(panel_y + 3, 4, "▼ DOWN  " + self._large_trend(
                    selected_row.get("graph_down"), width - 16), 1)
                self._write(panel_y + 4, 2,
                            "╰─ Past 10m trend (gaps = missing samples) " +
                            "─" * max(0, width - 55), 1)
            else:
                self._write(panel_y + 1, 4, "▲ " + self._large_trend(
                    selected_row.get("graph_up"), width - 9), 2)
                self._write(panel_y + 2, 4, "▼ " + self._large_trend(
                    selected_row.get("graph_down"), width - 9), 1)
        summary_y = panel_y + detail_height + 1
        if links and nic_slots and summary_y + nic_slots < footer_start:
            self._write(summary_y, 2,
                        f"NETWORK INTERFACES ({len(links)})  Tab/←→ to switch", 1, True)
            for i, link in enumerate(links[:nic_slots]):
                self._write(summary_y + 1 + i, 4,
                            f"{'▶' if link['interface'] == nic else ' '} "
                            f"{link['interface']:<16} "
                            f"↓{link['rx_mbps']:>9.1f}  ↑{link['tx_mbps']:>9.1f} Mb/s",
                            1 if link["interface"] == nic else 0,
                            link["interface"] == nic)
        if show_other and self.last and links:
            down, up = self.untracked_rates(interface, self.last.get("rows", []))
            if down + up >= .1:
                self._write(height - 5, 2,
                            f"OTHER / UNKNOWN ~  ↓{down:,.1f}  ↑{up:,.1f} Mb/s",
                            3, True)
        if self.last and self.last.get("speed_limits_error"):
            footer_note = "Speed-limit settings unavailable (check logs)"
        else:
            footer_note = "* incomplete measured history | GB = recorded bytes, NOT speed × time"
        self._write(height - 4, 2, footer_note, 3)
        self._write(height - 3, 1, "╰" + line + "╯", 1)
        self._write(height - 2, 2,
                    "↑↓ select | PgDn/PgUp or n/p page | Enter/q speed | Tab NIC | +/- refresh | Esc")
        state = ("History ON (background)" if self.last and
                 self.last.get("background_history_active") else "History: viewer only")
        self._write(height - 1, 2,
                    f"Page {page + 1}/{pages} • {len(rows)} ports • {nic} • {state}", 1)
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
