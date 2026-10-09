"""Text-only terminal dashboard with graceful small-terminal fallback."""
import os
import sys
from . import sampler
from .errors import PM2Error


OPTIONS = (
    ("01", "Network Dashboard"),
    ("02", "Tunnel Management"),
    ("03", "Port Mapping"),
    ("04", "Live Traffic Monitor"),
    ("05", "Bandwidth Limits (2.1+)"),
    ("06", "Traffic Reports"),
    ("07", "Firewall & Diagnostics"),
    ("08", "Backup & Restore"),
    ("09", "Settings / About"),
    ("00", "Exit"),
)


def menu():
    if not sys.stdin.isatty():
        raise PM2Error("E_VALIDATION", "Interactive dashboard needs a terminal; use --help")
    while True:
        width = max(35, min(72, os.get_terminal_size().columns)) if sys.stdout.isatty() else 48
        print("\n" + "=" * width)
        print(" PORT MANAGER 2 | Tunnel Edition | DEVELOPMENT")
        print("=" * width)
        for key, caption in OPTIONS:
            print(f" [{key}] {caption}")
        try:
            choice = input("Choice: ").strip().zfill(2)
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "00":
            return 0
        if choice == "06":
            try:
                for window in ("1h", "24h", "7d"):
                    row = sampler.report(window)
                    print(f" {window}: upload {row['upload_bytes']} bytes, "
                          f"download {row['download_bytes']} bytes, "
                          f"coverage {row['coverage_seconds']}s")
            except PM2Error as exc:
                print(f"[{exc.code}] {exc.message}")
        elif choice in {key for key, _ in OPTIONS}:
            print("Use 'portmanager2 help' for supported CLI commands.")
        else:
            print("Unknown menu selection.")
