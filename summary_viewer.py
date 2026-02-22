#!/usr/bin/env python3
"""Live terminal viewer for the connectivity-tester summary.csv file.

Redraws the table whenever the file is updated on disk.  Run in a second
terminal while dns_poller.py is running:

    python3 summary_viewer.py                        # watch ./summary.csv
    python3 summary_viewer.py --file /tmp/summary.csv
    python3 summary_viewer.py --interval 1           # check every 1 s
"""

import argparse
import csv
import os
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_CLEAR  = "\033[2J\033[H"   # clear screen then home cursor


def _error_color(rate: float) -> str:
    if rate == 0.0:
        return _GREEN
    if rate < 20.0:
        return _YELLOW
    return _RED


# ---------------------------------------------------------------------------
# Table rendering
# ---------------------------------------------------------------------------

# Each entry: (header label, CSV field name, right-align?)
_COLUMNS = [
    ("target",     "target",               False),
    ("type",       "type",                 False),
    ("total",      "total",                True),
    ("successes",  "successes",            True),
    ("errors",     "errors",               True),
    ("error %",    "error_rate_pct",       True),
    ("avg ms",     "avg_response_time_ms", True),
    ("min ms",     "min_response_time_ms", True),
    ("max ms",     "max_response_time_ms", True),
]

# Index of the error_rate_pct column (used for colouring).
_ERR_RATE_IDX = next(i for i, (_, f, _) in enumerate(_COLUMNS) if f == "error_rate_pct")


def _col_widths(rows: list[dict]) -> list[int]:
    widths = [len(hdr) for hdr, _, _ in _COLUMNS]
    for row in rows:
        for i, (_, field, _) in enumerate(_COLUMNS):
            widths[i] = max(widths[i], len(str(row.get(field, ""))))
    return widths


def _fmt_row(values: list[str], widths: list[int],
             bold: bool = False, color_idx: dict[int, str] | None = None) -> str:
    parts = []
    for i, ((_, _, right), w) in enumerate(zip(_COLUMNS, widths)):
        cell = values[i].rjust(w) if right else values[i].ljust(w)
        if color_idx and i in color_idx:
            cell = color_idx[i] + cell + _RESET
        if bold:
            cell = _BOLD + cell + _RESET
        parts.append(cell)
    return "  ".join(parts)


def render(rows: list[dict], path: str, mtime: float) -> str:
    updated = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    widths  = _col_widths(rows)
    sep     = "  ".join("─" * w for w in widths)
    headers = [hdr for hdr, _, _ in _COLUMNS]

    lines = [
        f"{_BOLD}Summary:{_RESET} {os.path.abspath(path)}",
        f"{_DIM}file updated {updated}  ·  viewer checked {now}  ·  Ctrl-C to quit{_RESET}",
        "",
        _fmt_row(headers, widths, bold=True),
        sep,
    ]

    for row in rows:
        values = [str(row.get(field, "")) for _, field, _ in _COLUMNS]
        try:
            rate = float(row.get("error_rate_pct", 0))
        except ValueError:
            rate = 0.0
        lines.append(_fmt_row(values, widths, color_idx={_ERR_RATE_IDX: _error_color(rate)}))

    if not rows:
        lines.append(f"  {_DIM}(no data yet){_RESET}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Live terminal viewer for connectivity-tester summary.csv",
    )
    parser.add_argument(
        "--file", default="summary.csv", metavar="FILE",
        help="Path to the summary CSV file (default: summary.csv)",
    )
    parser.add_argument(
        "--interval", type=float, default=0.5, metavar="SECS",
        help="How often to check for file changes in seconds (default: 0.5)",
    )
    args = parser.parse_args()

    last_mtime: float | None = None

    try:
        while True:
            # --- check if the file exists and has changed ---
            try:
                mtime = os.stat(args.file).st_mtime
            except FileNotFoundError:
                if last_mtime is not None:
                    # File disappeared after existing — reset so we redraw.
                    last_mtime = None
                sys.stdout.write(_CLEAR)
                sys.stdout.write(
                    f"{_BOLD}Summary:{_RESET} {os.path.abspath(args.file)}\n"
                    f"{_DIM}Waiting for file to be created...  Ctrl-C to quit{_RESET}\n"
                )
                sys.stdout.flush()
                time.sleep(args.interval)
                continue

            if mtime == last_mtime:
                time.sleep(args.interval)
                continue

            last_mtime = mtime

            # --- read and render ---
            try:
                with open(args.file, newline="") as f:
                    rows = list(csv.DictReader(f))
            except Exception as exc:
                sys.stdout.write(_CLEAR)
                sys.stdout.write(f"Error reading {args.file}: {exc}\n")
                sys.stdout.flush()
                time.sleep(args.interval)
                continue

            sys.stdout.write(_CLEAR)
            sys.stdout.write(render(rows, args.file, mtime) + "\n")
            sys.stdout.flush()

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print()   # leave the terminal on a clean line


if __name__ == "__main__":
    main()
