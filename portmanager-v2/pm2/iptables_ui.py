"""Read-only complete IPv4 iptables browser for Port Manager's Ports menu."""
import shutil
import textwrap

from . import system_rules


def browse():
    from . import simple_ui as ui
    rows, error = system_rules.detect_all()
    if error or not rows:
        ui._title("ALL IPTABLES RULES")
        ui._ui_edge("top")
        ui._ui_line(ui._paint("93", "  " + (error or "No rules found.")))
        ui._ui_edge("bottom")
        ui._ask("Enter to return")
        return
    page = 0
    while True:
        size = max(3, min(7, shutil.get_terminal_size((100, 28)).lines - 14))
        pages = (len(rows) + size - 1) // size
        page = min(page, pages - 1)
        offset = page * size
        chunk = rows[offset:offset + size]
        ui._title("ALL IPTABLES RULES")
        ui._ui_edge("top")
        ui._ui_line(f"  IPv4 tables/chains/rules  |  {len(rows)} lines  |  Page {page + 1}/{pages}")
        ui._ui_line(ui._paint("93", "  Includes manual, Docker, UFW, V1 and V2 rules (read-only)."))
        ui._ui_edge("rule")
        for index, line in enumerate(chunk, 1):
            owner = "PM2" if "PM2_" in line or "pm2:" in line else "OTHER"
            ui._ui_line(f"  [{index}] [{owner}] {ui._ui_cut(line, ui._ui_width() - 23)}")
        ui._ui_edge("bottom")
        choices = [(str(i), f"Full rule {offset+i}")
                   for i in range(1, len(chunk) + 1)]
        if page:
            choices.append(("8", "Previous page"))
        if page + 1 < pages:
            choices.append(("9", "Next page"))
        choices.append(("0", "Back to ports"))
        key = ui._choose(*choices)
        if key in (None, "0"):
            return
        if key == "8" and page:
            page -= 1
        elif key == "9" and page + 1 < pages:
            page += 1
        elif key and key.isdecimal() and 1 <= int(key) <= len(chunk):
            ui._title("IPTABLES RULE DETAILS")
            ui._ui_edge("top")
            for part in textwrap.wrap(ui._ui_clean(chunk[int(key)-1]),
                                      width=max(35, ui._ui_width()-10),
                                      break_long_words=True,
                                      break_on_hyphens=False):
                ui._ui_line("  " + part)
            ui._ui_edge("bottom")
            ui._choose(("0", "Back to rules"))


def full_reset_information():
    """Do not offer unsafe arbitrary global flush over an SSH session."""
    from . import simple_ui as ui
    ui._title("FULL IPTABLES RESET")
    ui._ui_edge("top")
    ui._ui_line(ui._paint("91;1", "  DANGER: impacts ALL IPv4 firewall rules and SSH access."))
    ui._ui_line("  Docker, UFW, manual rules and all tunnels would be affected.")
    ui._ui_line("  Use a provider console with a tested backup/rollback procedure.")
    ui._ui_line(ui._paint("93", "  No firewall rules are changed on this screen."))
    ui._ui_edge("bottom")
    ui._choose(("0", "Return without changes"))
