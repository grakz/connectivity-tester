#!/usr/bin/env python3
"""Connectivity poller driven by a JSON config file.

Polls one or more DNS domains and/or ICMP ping hosts at a configurable
interval. All targets are polled concurrently and anchored to a shared
tick grid so results are aligned in time.

CSV output:
  results.csv  — one row per time slot; every target occupies its own
                 column group (<target>_<type>_<field>)
  summary.csv  — running aggregate stats (totals, error rate, timings)
"""

import argparse
import csv
import json
import math
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

import dns.resolver
import dns.reversename
from icmplib import ping as icmp_ping
from icmplib import SocketPermissionError

# Use raw ICMP sockets when running as root, UDP otherwise (no root needed).
_PRIVILEGED = os.geteuid() == 0

# Lock so concurrent threads don't interleave their console output.
_print_lock = threading.Lock()


def _print(*args, **kwargs) -> None:
    with _print_lock:
        print(*args, **kwargs)


# ---------------------------------------------------------------------------
# Summary tracking
# ---------------------------------------------------------------------------

class _Stats:
    """Running totals for one (target, check-type) pair."""
    __slots__ = ("successes", "errors", "_sum", "_min", "_max")

    def __init__(self) -> None:
        self.successes = 0
        self.errors = 0
        self._sum = 0.0
        self._min = float("inf")
        self._max = 0.0

    def add(self, success: bool, response_time_ms: float) -> None:
        if success:
            self.successes += 1
        else:
            self.errors += 1
        # Only count timing when we actually measured something (not a 0-ms placeholder).
        if response_time_ms > 0:
            self._sum += response_time_ms
            if response_time_ms < self._min:
                self._min = response_time_ms
            if response_time_ms > self._max:
                self._max = response_time_ms

    @property
    def total(self) -> int:
        return self.successes + self.errors

    @property
    def error_rate_pct(self) -> float:
        return round(self.errors / self.total * 100, 1) if self.total else 0.0

    @property
    def avg_ms(self) -> float:
        timed = self.total if self._max > 0 else 0
        return round(self._sum / timed, 3) if timed else 0.0

    @property
    def min_ms(self) -> float:
        return round(self._min, 3) if self._min != float("inf") else 0.0

    @property
    def max_ms(self) -> float:
        return round(self._max, 3)


class ResultsWriter:
    """Thread-safe combined results CSV.

    One row per time slot; all targets contribute their own column group
    (<target>_<type>_<field>) to the same row.  The file is rewritten and
    flushed after every individual measurement so it is always current.
    """

    def __init__(self, output_file: str, fieldnames: list[str]) -> None:
        self._path = output_file
        self._fieldnames = fieldnames
        self._lock = threading.Lock()
        self._rows: dict[int, dict] = {}  # slot_index -> partial row

    def record(self, slot: int, data: dict) -> None:
        """Merge *data* into the row for *slot* and rewrite the file."""
        with self._lock:
            if slot not in self._rows:
                self._rows[slot] = {"slot": slot}
            self._rows[slot].update(data)
            self._flush()

    def _flush(self) -> None:
        """Rewrite the CSV. Must be called with self._lock held."""
        with open(self._path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self._fieldnames, restval="")
            writer.writeheader()
            for slot in sorted(self._rows):
                writer.writerow(self._rows[slot])


class SummaryTracker:
    """Accumulates per-target statistics and rewrites summary.csv after every update."""

    FIELDNAMES = [
        "target", "type", "total", "successes", "errors",
        "error_rate_pct", "avg_response_time_ms", "min_response_time_ms", "max_response_time_ms",
    ]

    def __init__(self, output_file: str = "summary.csv") -> None:
        self._path = output_file
        self._lock = threading.Lock()
        # Insertion-ordered dict so rows appear in registration order.
        self._data: dict[tuple[str, str], _Stats] = {}

    def register(self, target: str, check_type: str) -> None:
        """Pre-register a key to lock in its row position before polling starts."""
        self._data[(target, check_type)] = _Stats()

    def update(self, target: str, check_type: str,
               success: bool, response_time_ms: float) -> None:
        with self._lock:
            self._data[(target, check_type)].add(success, response_time_ms)
            self._flush()

    def _flush(self) -> None:
        """Rewrite the CSV atomically. Must be called with self._lock held."""
        with open(self._path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
            writer.writeheader()
            for (target, check_type), stats in self._data.items():
                writer.writerow({
                    "target": target,
                    "type": check_type,
                    "total": stats.total,
                    "successes": stats.successes,
                    "errors": stats.errors,
                    "error_rate_pct": stats.error_rate_pct,
                    "avg_response_time_ms": stats.avg_ms,
                    "min_response_time_ms": stats.min_ms,
                    "max_response_time_ms": stats.max_ms,
                })


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def reverse_lookup(ip: str) -> str:
    """Return the PTR hostname for an IP, or the IP itself if lookup fails."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(rev_name, "PTR", lifetime=2)
        return str(answer[0]).rstrip(".")
    except Exception:
        return ip


def dns_lookup(domain: str, resolver: dns.resolver.Resolver) -> dict:
    start = time.perf_counter()
    try:
        answer = resolver.resolve(domain, "A")
        elapsed_ms = (time.perf_counter() - start) * 1000
        ns_ip = answer.nameserver
        return {
            "success": True,
            "response_time_ms": round(elapsed_ms, 3),
            "resolved_ip": str(answer[0]),
            "dns_server_ip": ns_ip,
            "dns_server_name": reverse_lookup(ns_ip),
            "error": "",
        }
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {
            "success": False,
            "response_time_ms": round(elapsed_ms, 3),
            "resolved_ip": "",
            "dns_server_ip": "",
            "dns_server_name": "",
            "error": str(exc),
        }


def http_get(domain: str, timeout: float) -> dict:
    """Perform an HTTPS GET to *domain* and return timing + status information.

    Falls back to plain HTTP if the HTTPS attempt raises an SSL or connection
    error (not an HTTP-level error such as 4xx/5xx).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        start = time.perf_counter()
        try:
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": "connectivity-tester/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed_ms = (time.perf_counter() - start) * 1000
                return {
                    "http_success": resp.status == 200,
                    "http_status_code": resp.status,
                    "http_response_time_ms": round(elapsed_ms, 3),
                    "http_error": "",
                }
        except urllib.error.HTTPError as exc:
            # Server responded with a non-2xx code — that is a definitive answer.
            elapsed_ms = (time.perf_counter() - start) * 1000
            return {
                "http_success": False,
                "http_status_code": exc.code,
                "http_response_time_ms": round(elapsed_ms, 3),
                "http_error": f"HTTP {exc.code}: {exc.reason}",
            }
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            last_error = str(exc)
            last_elapsed = elapsed_ms
            # Only fall through to http:// on SSL / connection failures.
            if scheme == "https" and any(
                kw in type(exc).__name__ for kw in ("SSL", "Certificate", "timeout")
            ):
                continue
            return {
                "http_success": False,
                "http_status_code": 0,
                "http_response_time_ms": round(elapsed_ms, 3),
                "http_error": last_error,
            }

    return {
        "http_success": False,
        "http_status_code": 0,
        "http_response_time_ms": round(last_elapsed, 3),
        "http_error": last_error,
    }


def poll_dns(domain: str, interval: float, iterations: int,
             writer: ResultsWriter, resolver: dns.resolver.Resolver,
             http_check: bool = False, timeout: float = 5.0,
             summary: SummaryTracker | None = None,
             schedule_start: float | None = None) -> None:
    pad = len(str(iterations))
    t0 = schedule_start if schedule_start is not None else time.monotonic()

    next_slot = 0  # index of the next target tick: t0 + next_slot * interval
    for i in range(1, iterations + 1):
        current_slot = next_slot
        wait = (t0 + current_slot * interval) - time.monotonic()
        if wait > 0:
            time.sleep(wait)

        dns_timestamp = datetime.now().isoformat()
        dns_result = dns_lookup(domain, resolver)

        if summary:
            summary.update(domain, "dns", dns_result["success"], dns_result["response_time_ms"])

        row_data = {
            f"{domain}_dns_timestamp":       dns_timestamp,
            f"{domain}_dns_success":         dns_result["success"],
            f"{domain}_dns_response_time_ms": dns_result["response_time_ms"],
            f"{domain}_dns_resolved_ip":     dns_result["resolved_ip"],
            f"{domain}_dns_server_ip":       dns_result["dns_server_ip"],
            f"{domain}_dns_server_name":     dns_result["dns_server_name"],
            f"{domain}_dns_error":           dns_result["error"],
        }

        http_result: dict = {}
        if http_check:
            http_timestamp = datetime.now().isoformat()
            http_result = http_get(domain, timeout)
            if summary:
                summary.update(domain, "http", http_result["http_success"],
                               http_result["http_response_time_ms"])
            row_data.update({
                f"{domain}_http_timestamp":        http_timestamp,
                f"{domain}_http_success":          http_result["http_success"],
                f"{domain}_http_status_code":      http_result["http_status_code"],
                f"{domain}_http_response_time_ms": http_result["http_response_time_ms"],
                f"{domain}_http_error":            http_result["http_error"],
            })

        writer.record(current_slot, row_data)

        dns_status = "OK  " if dns_result["success"] else "FAIL"
        ns = dns_result["dns_server_name"] or dns_result["dns_server_ip"] or "-"
        line = (
            f"  [dns  {domain}  {i:>{pad}}/{iterations}]"
            f"  {dns_timestamp}"
            f"  DNS:{dns_status} {dns_result['response_time_ms']:7.1f} ms"
            f"  {dns_result['resolved_ip'] or dns_result['error']}"
            f"  (ns: {ns})"
        )
        if http_check:
            code = http_result["http_status_code"]
            h_ms = http_result["http_response_time_ms"]
            h_ok = "OK  " if http_result["http_success"] else "FAIL"
            line += (
                f"  |  HTTP:{h_ok} {h_ms:7.1f} ms"
                f"  [{code or http_result['http_error']}]"
            )
        _print(line)

        # Advance to the first slot that is strictly in the future.
        next_slot = math.floor((time.monotonic() - t0) / interval) + 1


# ---------------------------------------------------------------------------
# ICMP ping
# ---------------------------------------------------------------------------

def ping_host(host: str, timeout: float) -> dict:
    try:
        result = icmp_ping(host, count=1, timeout=timeout, privileged=_PRIVILEGED)
        rtt = round(result.avg_rtt, 3) if result.is_alive else 0.0
        return {
            "success": result.is_alive,
            "response_time_ms": rtt,
            "packets_sent": result.packets_sent,
            "packets_received": result.packets_received,
            "error": "",
        }
    except SocketPermissionError:
        # Fallback: retry without privileged raw sockets
        try:
            result = icmp_ping(host, count=1, timeout=timeout, privileged=False)
            rtt = round(result.avg_rtt, 3) if result.is_alive else 0.0
            return {
                "success": result.is_alive,
                "response_time_ms": rtt,
                "packets_sent": result.packets_sent,
                "packets_received": result.packets_received,
                "error": "",
            }
        except Exception as exc:
            return {
                "success": False,
                "response_time_ms": 0.0,
                "packets_sent": 1,
                "packets_received": 0,
                "error": str(exc),
            }
    except Exception as exc:
        return {
            "success": False,
            "response_time_ms": 0.0,
            "packets_sent": 1,
            "packets_received": 0,
            "error": str(exc),
        }


def poll_ping(host: str, interval: float, iterations: int,
              writer: ResultsWriter, timeout: float,
              summary: SummaryTracker | None = None,
              schedule_start: float | None = None) -> None:
    pad = len(str(iterations))
    t0 = schedule_start if schedule_start is not None else time.monotonic()

    next_slot = 0  # index of the next target tick: t0 + next_slot * interval
    for i in range(1, iterations + 1):
        current_slot = next_slot
        wait = (t0 + current_slot * interval) - time.monotonic()
        if wait > 0:
            time.sleep(wait)

        timestamp = datetime.now().isoformat()
        result = ping_host(host, timeout)

        if summary:
            summary.update(host, "ping", result["success"], result["response_time_ms"])

        writer.record(current_slot, {
            f"{host}_ping_timestamp":        timestamp,
            f"{host}_ping_success":          result["success"],
            f"{host}_ping_response_time_ms": result["response_time_ms"],
            f"{host}_ping_packets_sent":     result["packets_sent"],
            f"{host}_ping_packets_received": result["packets_received"],
            f"{host}_ping_error":            result["error"],
        })

        status = "OK  " if result["success"] else "FAIL"
        _print(
            f"  [ping {host}  {i:>{pad}}/{iterations}]"
            f"  {timestamp}  {status}"
            f"  {result['response_time_ms']:7.1f} ms"
            f"  {result['error'] if not result['success'] else ''}"
        )

        # Advance to the first slot that is strictly in the future.
        next_slot = math.floor((time.monotonic() - t0) / interval) + 1


# ---------------------------------------------------------------------------
# Config / helpers
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path) as f:
        config = json.load(f)

    missing = [k for k in ("interval", "iterations") if k not in config]
    if missing:
        sys.exit(f"Config missing required keys: {', '.join(missing)}")

    domains = config.get("domains", [])
    ping_hosts = config.get("ping_hosts", [])

    if not domains and not ping_hosts:
        sys.exit("Config must contain at least one of 'domains' or 'ping_hosts'.")
    if not isinstance(domains, list):
        sys.exit("Config 'domains' must be a list.")
    if not isinstance(ping_hosts, list):
        sys.exit("Config 'ping_hosts' must be a list.")

    return config


def build_resolver(config: dict) -> dns.resolver.Resolver:
    if "dns_server" in config:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [config["dns_server"]]
    else:
        try:
            resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            sys.exit(
                "No system DNS resolver found. "
                'Add a "dns_server" key to your config (e.g. "8.8.8.8").'
            )
    resolver.lifetime = config.get("timeout", 5.0)
    return resolver


def safe_filename(name: str) -> str:
    """Replace characters that are awkward in filenames."""
    for ch in (":", "/", "\\", "*", "?", '"', "<", ">", "|"):
        name = name.replace(ch, "_")
    return name


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Poll DNS domains and/or ICMP ping hosts; write combined results.csv."
    )
    parser.add_argument(
        "--config", default="config.json", metavar="FILE",
        help="Path to JSON config file (default: config.json)",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    interval: float = config["interval"]
    iterations: int = config["iterations"]
    timeout: float = config.get("timeout", 5.0)
    domains: list[str] = config.get("domains", [])
    ping_hosts: list[str] = config.get("ping_hosts", [])
    http_check: bool = bool(config.get("http_check", False))

    print(f"Config     : {args.config}")
    print(f"Interval   : {interval}s  |  Iterations: {iterations}  |  Timeout: {timeout}s")
    if domains:
        print(f"DNS domains: {', '.join(domains)}"
              + ("  (+HTTP check)" if http_check else ""))
        if "dns_server" in config:
            print(f"DNS server : {config['dns_server']}")
    if ping_hosts:
        print(f"Ping hosts : {', '.join(ping_hosts)}")
    print(f"Results    : results.csv")
    print(f"Summary    : summary.csv")
    print()

    resolver = build_resolver(config) if domains else None

    # Pre-register targets in config order so summary rows are always stable.
    summary = SummaryTracker("summary.csv")
    for domain in domains:
        summary.register(domain, "dns")
        if http_check:
            summary.register(domain, "http")
    for host in ping_hosts:
        summary.register(host, "ping")

    # Build the combined results CSV column list in config order.
    fieldnames = ["slot"]
    for domain in domains:
        for col in ["timestamp", "success", "response_time_ms",
                    "resolved_ip", "server_ip", "server_name", "error"]:
            fieldnames.append(f"{domain}_dns_{col}")
        if http_check:
            for col in ["timestamp", "success", "status_code",
                        "response_time_ms", "error"]:
                fieldnames.append(f"{domain}_http_{col}")
    for host in ping_hosts:
        for col in ["timestamp", "success", "response_time_ms",
                    "packets_sent", "packets_received", "error"]:
            fieldnames.append(f"{host}_ping_{col}")
    results_writer = ResultsWriter("results.csv", fieldnames)

    # Shared anchor for the tick grid — all threads target t0 + n*interval.
    schedule_start = time.monotonic()

    threads: list[threading.Thread] = []

    for domain in domains:
        t = threading.Thread(
            target=poll_dns,
            args=(domain, interval, iterations, results_writer, resolver,
                  http_check, timeout, summary, schedule_start),
            name=f"dns-{domain}",
            daemon=True,
        )
        threads.append(t)

    for host in ping_hosts:
        t = threading.Thread(
            target=poll_ping,
            args=(host, interval, iterations, results_writer, timeout,
                  summary, schedule_start),
            name=f"ping-{host}",
            daemon=True,
        )
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"\n  -> results.csv written ({iterations} slots)")
    print(f"  -> summary.csv written")


if __name__ == "__main__":
    main()
