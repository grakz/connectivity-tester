#!/usr/bin/env python3
"""Live terminal viewer for the connectivity-tester summary.csv file.

Redraws the table whenever the file is updated on disk.  Run in a second
terminal while dns_poller.py is running:

    python3 summary_viewer.py                        # watch ./summary.csv
    python3 summary_viewer.py --file /tmp/summary.csv
    python3 summary_viewer.py --interval 1           # check every 1 s

After 100 iterations the viewer also reads results.csv and shows a timing-
event table: the ±2-row context window around the most recent slot where any
target failed outright or exceeded mean + 2·stdev response time.
"""

import argparse
import csv
import os
import re
import statistics
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
# Summary table rendering
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

# Fields that should always be rendered with exactly 3 decimal places so the
# column width stays stable as values change (e.g. "123.5" → "123.500").
_MS_FIELDS = {"avg_response_time_ms", "min_response_time_ms", "max_response_time_ms"}


def _fmt_value(field: str, raw: str) -> str:
    if field in _MS_FIELDS and raw:
        try:
            return f"{float(raw):.3f}"
        except ValueError:
            pass
    return raw


def _col_widths(rows: list[dict]) -> list[int]:
    widths = [len(hdr) for hdr, _, _ in _COLUMNS]
    for row in rows:
        for i, (_, field, _) in enumerate(_COLUMNS):
            # Use the formatted value so widths account for 3-decimal expansion.
            widths[i] = max(widths[i], len(_fmt_value(field, str(row.get(field, "")))))
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
        values = [_fmt_value(field, str(row.get(field, ""))) for _, field, _ in _COLUMNS]
        try:
            rate = float(row.get("error_rate_pct", 0))
        except ValueError:
            rate = 0.0
        lines.append(_fmt_row(values, widths, color_idx={_ERR_RATE_IDX: _error_color(rate)}))

    if not rows:
        lines.append(f"  {_DIM}(no data yet){_RESET}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Results analysis — stddev, event detection, event table
# ---------------------------------------------------------------------------

def _parse_target_types(fieldnames: list[str]) -> list[tuple[str, str]]:
    """Return (target, type) pairs inferred from results.csv column names.

    Column names follow the pattern <target>_(dns|http|ping)_<field>.
    We anchor on the *_success suffix to identify target+type pairs; the
    greedy regex correctly handles targets that themselves contain underscores.
    """
    result = []
    for col in fieldnames:
        m = re.match(r"^(.+)_(dns|http|ping)_success$", col)
        if m:
            result.append((m.group(1), m.group(2)))
    return result


def _process_results(rows: list[dict]) -> dict:
    """Analyse results.csv rows: compute per-target stats and find the last
    timing event.

    An event is any slot where a target either failed outright or had a
    response time exceeding mean + 2·stdev (computed over all successful
    measurements).  Event detection is only active after 100 slots.
    """
    if not rows:
        return {"has_stats": False, "target_types": [], "total_slots": 0}

    fieldnames = list(rows[0].keys())
    target_types = _parse_target_types(fieldnames)

    # Index rows by slot; collect successful response times per target+type.
    rows_by_slot: dict[int, dict] = {}
    rt_values: dict[tuple, list[float]] = {tt: [] for tt in target_types}

    for row in rows:
        try:
            slot = int(row["slot"])
        except (KeyError, ValueError):
            continue
        rows_by_slot[slot] = row
        for tt in target_types:
            target, type_ = tt
            if row.get(f"{target}_{type_}_success") == "True":
                rt_str = row.get(f"{target}_{type_}_response_time_ms", "")
                try:
                    rt_values[tt].append(float(rt_str))
                except ValueError:
                    pass

    sorted_slots = sorted(rows_by_slot)
    total_slots  = len(sorted_slots)
    has_stats    = total_slots >= 100

    # Compute mean, stdev, and spike threshold for each target+type.
    thresholds: dict[tuple, float] = {}
    means: dict[tuple, float] = {}
    if has_stats:
        for tt, vals in rt_values.items():
            if len(vals) >= 2:
                mean = statistics.mean(vals)
                stdev = statistics.stdev(vals)
                means[tt] = mean
                thresholds[tt] = mean + 2 * stdev

    # Scan slots in order to find the last event slot.
    last_event_slot: int | None = None
    event_triggers: set[tuple] = set()

    if has_stats:
        for slot in sorted_slots:
            row = rows_by_slot[slot]
            triggers: set[tuple] = set()
            for tt in target_types:
                target, type_ = tt
                success = row.get(f"{target}_{type_}_success", "")
                if not success:
                    continue  # no measurement for this target in this slot
                rt_str = row.get(f"{target}_{type_}_response_time_ms", "")
                is_event = (success == "False")
                if not is_event and tt in thresholds and rt_str:
                    try:
                        is_event = float(rt_str) > thresholds[tt]
                    except ValueError:
                        pass
                if is_event:
                    triggers.add(tt)
            if triggers:
                last_event_slot = slot
                event_triggers  = triggers

    return {
        "has_stats":        has_stats,
        "target_types":     target_types,
        "total_slots":      total_slots,
        "thresholds":       thresholds,
        "means":            means,
        "last_event_slot":  last_event_slot,
        "event_triggers":   event_triggers,
        "rows_by_slot":     rows_by_slot,
        "sorted_slots":     sorted_slots,
    }


def render_event_table(data: dict) -> str:
    """Render the timing-event context table below the summary."""
    if not data:
        return (
            f"{_BOLD}Timing events:{_RESET}\n"
            f"  {_DIM}(results.csv not available yet){_RESET}"
        )

    total_slots = data.get("total_slots", 0)
    if not data.get("has_stats"):
        needed = 100 - total_slots
        return (
            f"{_BOLD}Timing events:{_RESET}\n"
            f"  {_DIM}Event detection active after 100 iterations "
            f"({needed} more needed){_RESET}"
        )

    last_event_slot = data["last_event_slot"]
    if last_event_slot is None:
        return (
            f"{_BOLD}Timing events:{_RESET}\n"
            f"  {_DIM}No events detected (threshold: mean + 2·stdev per target){_RESET}"
        )

    target_types   = data["target_types"]
    rows_by_slot   = data["rows_by_slot"]
    sorted_slots   = data["sorted_slots"]
    event_triggers = data["event_triggers"]
    thresholds     = data["thresholds"]

    # Find the ±2 row context window around the event slot.
    event_idx    = sorted_slots.index(last_event_slot)
    context_slots = [
        sorted_slots[event_idx + offset]
        if 0 <= event_idx + offset < len(sorted_slots) else None
        for offset in (-2, -1, 0, 1, 2)
    ]

    # Pull the event timestamp from the first available target in that slot.
    event_row = rows_by_slot[last_event_slot]
    event_ts  = ""
    for target, type_ in target_types:
        ts = event_row.get(f"{target}_{type_}_timestamp", "")
        if ts:
            event_ts = ts[:19].replace("T", " ")
            break

    # Build per-row display values and cell classifications.
    # Layout: [target, type, t-2, t-1, t, t+1, t+2]
    # Cell kinds: "normal" | "spike" | "fail" | "missing"
    _EVENT_COL = 4   # index of the "t" column in the row

    table_rows: list[tuple[tuple, list[str], list[str]]] = []
    for tt in target_types:
        target, type_ = tt
        display: list[str] = [target, type_]
        kinds:   list[str] = ["normal", "normal"]
        for slot in context_slots:
            if slot is None:
                display.append("—"); kinds.append("missing"); continue
            row     = rows_by_slot.get(slot, {})
            success = row.get(f"{target}_{type_}_success", "")
            rt_str  = row.get(f"{target}_{type_}_response_time_ms", "")
            if not success:
                display.append("—"); kinds.append("missing")
            elif success == "False":
                display.append("FAIL"); kinds.append("fail")
            elif rt_str:
                try:
                    rt   = float(rt_str)
                    kind = "spike" if (tt in thresholds and rt > thresholds[tt]) else "normal"
                    display.append(f"{rt:.3f}"); kinds.append(kind)
                except ValueError:
                    display.append(rt_str); kinds.append("normal")
            else:
                display.append("—"); kinds.append("missing")
        table_rows.append((tt, display, kinds))

    # Column headers; "t" is bold to mark the event column.
    col_labels = ["t-2", "t-1", "t", "t+1", "t+2"]
    headers    = ["target", "type"] + col_labels

    # Compute column widths from display values.
    widths = [len(h) for h in headers]
    for _, display, _ in table_rows:
        for i, v in enumerate(display):
            widths[i] = max(widths[i], len(v))

    RIGHT_COLS = set(range(2, 7))  # ms columns are right-aligned

    def _hdr_cell(label: str, idx: int) -> str:
        aligned = label.rjust(widths[idx]) if idx in RIGHT_COLS else label.ljust(widths[idx])
        # Event column: bold + yellow; all other headers: just bold.
        if idx == _EVENT_COL:
            return _BOLD + _YELLOW + aligned + _RESET
        return _BOLD + aligned + _RESET

    def _data_cell(val: str, kind: str, idx: int) -> str:
        aligned = val.rjust(widths[idx]) if idx in RIGHT_COLS else val.ljust(widths[idx])
        if kind == "fail":
            return _RED + aligned + _RESET
        if kind == "spike":
            return _YELLOW + aligned + _RESET
        return aligned

    sep    = "  ".join("─" * w for w in widths)
    header = "  ".join(_hdr_cell(h, i) for i, h in enumerate(headers))

    lines = [
        f"{_BOLD}Last timing event:{_RESET}  "
        f"slot {last_event_slot}  {_DIM}{event_ts}{_RESET}",
        "",
        f"  {header}",   # each cell already carries its own bold/colour
        f"  {sep}",
    ]
    for _, display, kinds in table_rows:
        cells = [_data_cell(display[i], kinds[i], i) for i in range(len(headers))]
        lines.append("  " + "  ".join(cells))

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
        "--results", default="results.csv", metavar="FILE",
        help="Path to the results CSV file for event detection (default: results.csv)",
    )
    parser.add_argument(
        "--interval", type=float, default=0.5, metavar="SECS",
        help="How often to check for file changes in seconds (default: 0.5)",
    )
    args = parser.parse_args()

    # Summary state
    last_summary_mtime:        float | None = None
    last_summary_rows:         list[dict]   = []
    last_summary_display_mtime: float | None = None

    # Results state
    last_results_mtime: float | None = None
    last_results_data:  dict         = {}

    try:
        while True:
            need_redraw = False

            # ── summary.csv ───────────────────────────────────────────────
            try:
                s_mtime = os.stat(args.file).st_mtime
            except FileNotFoundError:
                if last_summary_mtime is not None:
                    last_summary_mtime = None
                sys.stdout.write(_CLEAR)
                sys.stdout.write(
                    f"{_BOLD}Summary:{_RESET} {os.path.abspath(args.file)}\n"
                    f"{_DIM}Waiting for file to be created...  Ctrl-C to quit{_RESET}\n"
                )
                sys.stdout.flush()
                time.sleep(args.interval)
                continue

            if s_mtime != last_summary_mtime:
                try:
                    with open(args.file, newline="") as f:
                        s_rows = list(csv.DictReader(f))
                except Exception:
                    s_rows = None   # mid-write; don't advance mtime

                if s_rows is None:
                    pass            # retry next cycle
                elif not s_rows and last_summary_rows:
                    pass            # mid-write truncation; retry
                else:
                    last_summary_mtime = s_mtime
                    if s_rows:
                        last_summary_rows          = s_rows
                        last_summary_display_mtime = s_mtime
                    need_redraw = True

            # ── results.csv ───────────────────────────────────────────────
            try:
                r_mtime = os.stat(args.results).st_mtime
            except FileNotFoundError:
                pass    # optional; absence is fine before poller starts
            else:
                if r_mtime != last_results_mtime:
                    try:
                        with open(args.results, newline="") as f:
                            r_rows = list(csv.DictReader(f))
                    except Exception:
                        r_rows = None   # mid-write

                    if r_rows is None:
                        pass            # retry next cycle
                    elif not r_rows and last_results_data:
                        pass            # mid-write truncation; retry
                    else:
                        last_results_mtime = r_mtime
                        if r_rows:
                            last_results_data = _process_results(r_rows)
                        need_redraw = True

            # ── redraw ────────────────────────────────────────────────────
            if need_redraw:
                out  = render(last_summary_rows, args.file,
                              last_summary_display_mtime or s_mtime)
                out += "\n\n"
                out += render_event_table(last_results_data)
                sys.stdout.write(_CLEAR)
                sys.stdout.write(out + "\n")
                sys.stdout.flush()

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print()   # leave the terminal on a clean line


if __name__ == "__main__":
    main()
