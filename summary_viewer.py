#!/usr/bin/env python3
"""Live terminal viewer for the connectivity-tester summary.csv file.

Redraws the table whenever the file is updated on disk.  Run in a second
terminal while dns_poller.py is running:

    python3 summary_viewer.py                        # watch ./summary.csv
    python3 summary_viewer.py --file /tmp/summary.csv
    python3 summary_viewer.py --interval 1           # check every 1 s
    python3 summary_viewer.py --sigma 3              # spike = mean + 3·stdev
    python3 summary_viewer.py --no-ping-events       # only dns/http trigger events

After 100 iterations the viewer reads results.csv and shows a timing-event
table.  The baseline (mean + stdev) is computed once from the first 100 slots
with outlier removal, so the event threshold stays fixed for the whole run.

Keyboard shortcuts (shown in the on-screen tooltip):
    a   previous timing event
    d   next timing event
    w   increase sigma by 1  (min 2.0)
    s   decrease sigma by 1  (min 2.0)
"""

import argparse
import csv
import os
import re
import statistics
import sys
import time
from datetime import datetime

# Optional keyboard support (Unix only)
try:
    import select
    import termios
    _KEYBOARD = sys.stdin.isatty()
except ImportError:
    _KEYBOARD = False

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

_ERR_RATE_IDX = next(i for i, (_, f, _) in enumerate(_COLUMNS) if f == "error_rate_pct")
_MS_FIELDS    = {"avg_response_time_ms", "min_response_time_ms", "max_response_time_ms"}


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
# Results analysis — frozen baseline, event detection, event table
# ---------------------------------------------------------------------------

def _parse_target_types(fieldnames: list[str]) -> list[tuple[str, str]]:
    """Return (target, type) pairs inferred from results.csv column names."""
    result = []
    for col in fieldnames:
        m = re.match(r"^(.+)_(dns|http|ping)_success$", col)
        if m:
            result.append((m.group(1), m.group(2)))
    return result


def _process_results(rows: list[dict], sigma: float = 2.0,
                     no_ping_events: bool = False) -> dict:
    """Analyse results.csv rows: compute a frozen baseline and detect events.

    Baseline is computed from the first 100 slots only, with two-pass outlier
    removal (values beyond sigma·stdev from the initial mean are excluded before
    the final mean/stdev are calculated).  This keeps the event threshold stable
    throughout a long run — events cannot appear or disappear as the average
    shifts over time.

    ``no_ping_events`` prevents ping measurements from triggering events (they
    are still shown in the event context table).
    """
    if not rows:
        return {
            "has_stats": False, "target_types": [], "total_slots": 0,
            "sigma": sigma, "events": [], "rows_by_slot": {}, "sorted_slots": [],
            "thresholds": {}, "baselines": {},
        }

    fieldnames   = list(rows[0].keys())
    target_types = _parse_target_types(fieldnames)

    # Index all rows by slot number.
    rows_by_slot: dict[int, dict] = {}
    for row in rows:
        try:
            slot = int(row["slot"])
        except (KeyError, ValueError):
            continue
        rows_by_slot[slot] = row

    sorted_slots = sorted(rows_by_slot)
    total_slots  = len(sorted_slots)
    has_stats    = total_slots >= 100

    # ── Frozen baseline from the first 100 slots ────────────────────────────
    # Two-pass: compute initial mean/stdev, remove outliers, recompute.
    thresholds: dict[tuple, float] = {}
    baselines:  dict[tuple, dict]  = {}   # mean, stdev, threshold — for display
    if has_stats:
        baseline_slots = sorted_slots[:100]
        for tt in target_types:
            target, type_ = tt
            vals: list[float] = []
            for slot in baseline_slots:
                r = rows_by_slot[slot]
                if r.get(f"{target}_{type_}_success") == "True":
                    rt_str = r.get(f"{target}_{type_}_response_time_ms", "")
                    try:
                        vals.append(float(rt_str))
                    except ValueError:
                        pass
            if len(vals) < 2:
                continue
            m1 = statistics.mean(vals)
            s1 = statistics.stdev(vals)
            # Remove outliers beyond 2·stdev and recompute.
            # Always uses sigma=2 regardless of the user's detection sigma,
            # so the baseline mean/stdev are stable and independent of it.
            clean = [v for v in vals if abs(v - m1) <= 2.0 * s1]
            if len(clean) >= 2:
                m2 = statistics.mean(clean)
                s2 = statistics.stdev(clean)
            else:
                m2, s2 = m1, s1
            threshold       = m2 + sigma * s2
            thresholds[tt]  = threshold
            baselines[tt]   = {
                "mean":      round(m2, 3),
                "stdev":     round(s2, 3),
                "threshold": round(threshold, 3),
            }

    # ── Scan all slots to build the ordered list of timing events ───────────
    events: list[dict] = []
    if has_stats:
        for slot in sorted_slots:
            row      = rows_by_slot[slot]
            triggers: set[tuple] = set()
            for tt in target_types:
                target, type_ = tt
                if no_ping_events and type_ == "ping":
                    continue  # excluded from event triggering
                success = row.get(f"{target}_{type_}_success", "")
                if not success:
                    continue  # target not measured in this slot
                rt_str   = row.get(f"{target}_{type_}_response_time_ms", "")
                is_event = (success == "False")
                if not is_event and tt in thresholds and rt_str:
                    try:
                        is_event = float(rt_str) > thresholds[tt]
                    except ValueError:
                        pass
                if is_event:
                    triggers.add(tt)
            if triggers:
                events.append({"slot": slot, "triggers": frozenset(triggers)})

    return {
        "has_stats":    has_stats,
        "target_types": target_types,
        "total_slots":  total_slots,
        "sigma":        sigma,
        "thresholds":   thresholds,
        "baselines":    baselines,
        "events":       events,
        "rows_by_slot": rows_by_slot,
        "sorted_slots": sorted_slots,
    }


def _render_baseline_table(data: dict) -> str:
    """Render the frozen baseline stats (avg, std, threshold) for every target."""
    baselines = data.get("baselines", {})
    sigma     = data.get("sigma", 2.0)
    if not baselines:
        return ""

    headers = ["target", "type", "avg ms", "std ms", f"avg + {sigma:g}·std  (threshold)"]
    rows = [
        [target, type_,
         f"{b['mean']:.3f}", f"{b['stdev']:.3f}", f"{b['threshold']:.3f}"]
        for (target, type_), b in baselines.items()
    ]

    widths = [len(h) for h in headers]
    for row in rows:
        for i, v in enumerate(row):
            widths[i] = max(widths[i], len(v))

    RIGHT = set(range(2, len(headers)))

    def _hdr(label: str, idx: int) -> str:
        aligned = label.rjust(widths[idx]) if idx in RIGHT else label.ljust(widths[idx])
        return _BOLD + aligned + _RESET

    def _cell(val: str, idx: int) -> str:
        aligned = val.rjust(widths[idx]) if idx in RIGHT else val.ljust(widths[idx])
        if idx == len(headers) - 1:          # threshold column — highlight
            return _YELLOW + _BOLD + aligned + _RESET
        return aligned

    sep    = "  ".join("─" * w for w in widths)
    header = "  ".join(_hdr(h, i) for i, h in enumerate(headers))
    lines  = [
        f"{_BOLD}Baseline{_RESET}  "
        f"{_DIM}(frozen from first 100 iterations, outlier removal \u03c3=2){_RESET}",
        f"  {header}",
        f"  {sep}",
    ]
    for row in rows:
        lines.append("  " + "  ".join(_cell(v, i) for i, v in enumerate(row)))
    return "\n".join(lines)


def render_event_table(data: dict, view_idx: int | None) -> str:
    """Render the timing-event context table.

    ``data`` is the high-water-mark processed results (never regresses).
    ``view_idx`` is None for auto-follow-latest or an int index into the events
    list for pinned navigation.
    """
    if not data:
        return (
            f"{_BOLD}Timing events:{_RESET}\n"
            f"  {_DIM}(results.csv not available yet){_RESET}"
        )

    total_slots = data.get("total_slots", 0)
    sigma       = data.get("sigma", 2.0)

    if not data.get("has_stats"):
        needed = 100 - total_slots
        return (
            f"{_BOLD}Timing events:{_RESET}\n"
            f"  {_DIM}Event detection active after 100 iterations "
            f"({needed} more needed){_RESET}"
        )

    events = data.get("events", [])
    total_events = len(events)

    if total_events == 0:
        baseline_section = _render_baseline_table(data)
        no_events_msg = (
            f"{_BOLD}Timing events:{_RESET}\n"
            f"  {_DIM}No events detected{_RESET}"
        )
        return no_events_msg + ("\n\n" + baseline_section if baseline_section else "")

    # Resolve which event to display.
    if view_idx is None:
        actual_idx = total_events - 1   # auto-follow latest
    else:
        actual_idx = max(0, min(view_idx, total_events - 1))

    ev              = events[actual_idx]
    event_slot      = ev["slot"]
    event_triggers  = ev["triggers"]
    target_types    = data["target_types"]
    rows_by_slot    = data["rows_by_slot"]
    sorted_slots    = data["sorted_slots"]
    thresholds      = data["thresholds"]

    # ── Navigation header ───────────────────────────────────────────────────
    nav_label = f"event {actual_idx + 1} of {total_events}"
    if view_idx is None:
        nav_label += "  (latest)"

    # ── Event timestamp ─────────────────────────────────────────────────────
    event_row = rows_by_slot[event_slot]
    event_ts  = ""
    for target, type_ in target_types:
        ts = event_row.get(f"{target}_{type_}_timestamp", "")
        if ts:
            event_ts = ts[:19].replace("T", " ")
            break

    # ── Context window: ±2 rows in the data around the event slot ───────────
    try:
        event_pos = sorted_slots.index(event_slot)
    except ValueError:
        event_pos = 0
    context_slots = [
        sorted_slots[event_pos + offset]
        if 0 <= event_pos + offset < len(sorted_slots) else None
        for offset in (-2, -1, 0, 1, 2)
    ]

    # ── Build per-row display values ────────────────────────────────────────
    # Layout: [target, type, t-2, t-1, t, t+1, t+2]
    # Cell kinds: "normal" | "spike" | "fail" | "missing"
    _EVENT_COL = 4

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

    # ── Column headers ───────────────────────────────────────────────────────
    col_labels = ["t-2", "t-1", "t", "t+1", "t+2"]
    headers    = ["target", "type"] + col_labels

    widths = [len(h) for h in headers]
    for _, display, _ in table_rows:
        for i, v in enumerate(display):
            widths[i] = max(widths[i], len(v))

    RIGHT_COLS = set(range(2, 7))

    def _hdr_cell(label: str, idx: int) -> str:
        aligned = label.rjust(widths[idx]) if idx in RIGHT_COLS else label.ljust(widths[idx])
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
        f"{_BOLD}Timing event  {nav_label}:{_RESET}  "
        f"slot {event_slot}  {_DIM}{event_ts}{_RESET}",
        "",
        f"  {header}",
        f"  {sep}",
    ]
    for _, display, kinds in table_rows:
        cells = [_data_cell(display[i], kinds[i], i) for i in range(len(headers))]
        lines.append("  " + "  ".join(cells))

    baseline_section = _render_baseline_table(data)
    if baseline_section:
        lines.append("")
        lines.append(baseline_section)

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
        "--sigma", type=float, default=2.0, metavar="N",
        help="Standard deviations above mean to flag as a timing event (default: 2.0)",
    )
    parser.add_argument(
        "--no-ping-events", action="store_true",
        help="Exclude ping results from triggering timing events",
    )
    parser.add_argument(
        "--interval", type=float, default=0.5, metavar="SECS",
        help="How often to check for file changes in seconds (default: 0.5)",
    )
    args = parser.parse_args()

    # Runtime-adjustable sigma (keyboard w/s).
    sigma = max(2.0, args.sigma)

    # Summary state.
    last_summary_mtime:         float | None = None
    last_summary_rows:          list[dict]   = []
    last_summary_display_mtime: float | None = None

    # Results state.
    # last_results_data is the high-water-mark: only updated when the new read
    # has at least as many slots as the current best.  This prevents a partial
    # mid-write read from reverting has_stats to False or losing recent events.
    last_results_mtime: float | None = None
    last_results_data:  dict         = {}

    # Navigation state: None = auto-follow latest, int = pinned index.
    view_idx: int | None = None

    # ── Terminal setup ───────────────────────────────────────────────────────
    kb = _KEYBOARD
    fd: int = -1
    old_term = None
    if kb:
        try:
            fd       = sys.stdin.fileno()
            old_term = termios.tcgetattr(fd)
            # Explicitly disable canonical mode AND echo.
            # tty.cbreak() does not clear ECHO in Python < 3.12, which causes
            # pressed keys to appear on screen and, more importantly, to be
            # delivered via the line-buffered TextIOWrapper rather than the raw
            # fd — making sys.stdin.read(1) unreliable after select().
            new_term    = list(old_term)
            new_term[3] = new_term[3] & ~(termios.ICANON | termios.ECHO)
            new_term[6] = list(old_term[6])          # deep-copy cc array
            new_term[6][termios.VMIN]  = 1           # return after 1 byte
            new_term[6][termios.VTIME] = 0           # no timeout
            termios.tcsetattr(fd, termios.TCSADRAIN, new_term)
        except Exception:
            kb = False

    def _do_redraw(s_mtime: float) -> None:
        """Clear screen and write the full combined display."""
        out  = render(last_summary_rows, args.file,
                      last_summary_display_mtime or s_mtime)
        out += "\n\n"
        out += render_event_table(last_results_data, view_idx)

        # Tooltip anchored to the bottom of the terminal.
        sigma_val = last_results_data.get("sigma", sigma)
        tip = (
            f"  {_DIM}a: prev event  "
            f"d: next event  "
            f"w: \u03c3+1  "
            f"s: \u03c3-1  "
            f"(\u03c3={sigma_val:g})"
            f"{_RESET}"
        )
        if kb:
            try:
                rows_t = os.get_terminal_size().lines
                tip = f"\033[{rows_t};1H{tip}"
            except OSError:
                tip = "\n" + tip

        sys.stdout.write(_CLEAR)
        sys.stdout.write(out + "\n")
        sys.stdout.write(tip)
        sys.stdout.flush()

    def _reprocess_sigma(new_sigma: float) -> None:
        """Reprocess results with the new sigma and update all state."""
        nonlocal sigma, last_results_data, view_idx
        sigma = new_sigma
        rows_by_slot = last_results_data.get("rows_by_slot", {})
        if not rows_by_slot:
            return
        # Reconstruct the ordered row list from the already-held index.
        rows = [rows_by_slot[s] for s in last_results_data["sorted_slots"]]
        new_data = _process_results(rows, sigma, args.no_ping_events)
        last_results_data = new_data
        # Clamp view_idx if events list shrank.
        n = len(new_data.get("events", []))
        if view_idx is not None and (n == 0 or view_idx >= n):
            view_idx = None

    try:
        while True:
            need_redraw = False
            s_mtime     = 0.0

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
                if kb:
                    try:
                        select.select([sys.stdin], [], [], args.interval)
                    except (ValueError, OSError):
                        time.sleep(args.interval)
                else:
                    time.sleep(args.interval)
                continue

            if s_mtime != last_summary_mtime:
                try:
                    with open(args.file, newline="") as f:
                        s_rows = list(csv.DictReader(f))
                except Exception:
                    s_rows = None

                if s_rows is None:
                    pass
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
                pass    # not yet created; that's fine
            else:
                if r_mtime != last_results_mtime:
                    try:
                        with open(args.results, newline="") as f:
                            r_rows = list(csv.DictReader(f))
                    except Exception:
                        r_rows = None

                    if r_rows is None:
                        pass
                    elif not r_rows and last_results_data:
                        pass        # mid-write truncation; retry
                    else:
                        last_results_mtime = r_mtime
                        if r_rows:
                            new_data = _process_results(
                                r_rows, sigma, args.no_ping_events)
                            # Only adopt the new analysis if it has at least as
                            # many slots as we already know about — prevents a
                            # partial mid-write read from reverting has_stats or
                            # losing events that we already displayed.
                            old_total = last_results_data.get("total_slots", 0)
                            if new_data["total_slots"] >= old_total:
                                last_results_data = new_data
                        need_redraw = True

            # ── redraw from file changes ───────────────────────────────────
            if need_redraw:
                _do_redraw(s_mtime)

            # ── keyboard input (blocks up to args.interval) ───────────────
            if kb:
                try:
                    ready, _, _ = select.select([sys.stdin], [], [], args.interval)
                except (ValueError, OSError):
                    time.sleep(args.interval)
                    continue

                if ready:
                    try:
                        # Read directly from the raw fd — bypasses
                        # TextIOWrapper buffering which can stall after select().
                        raw = os.read(fd, 1)
                        key = raw.decode("utf-8", errors="ignore") if raw else ""
                    except OSError:
                        key = ""

                    events     = last_results_data.get("events", [])
                    n_events   = len(events)
                    key_redraw = True

                    if key == "a":
                        # Previous event.
                        if view_idx is None:
                            view_idx = max(0, n_events - 2)
                        elif view_idx > 0:
                            view_idx -= 1
                        else:
                            key_redraw = False   # already at first
                    elif key == "d":
                        # Next event.
                        if view_idx is None:
                            key_redraw = False   # already at latest
                        elif view_idx >= n_events - 1:
                            view_idx = None      # snap back to auto-follow
                        else:
                            view_idx += 1
                    elif key == "w":
                        _reprocess_sigma(round(sigma + 1.0, 10))
                    elif key == "s":
                        _reprocess_sigma(max(2.0, round(sigma - 1.0, 10)))
                    else:
                        key_redraw = False

                    if key_redraw:
                        _do_redraw(s_mtime)
            else:
                time.sleep(args.interval)

    except KeyboardInterrupt:
        pass
    finally:
        if kb and old_term is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_term)
            except Exception:
                pass
        print()   # leave terminal on a clean line


if __name__ == "__main__":
    main()
