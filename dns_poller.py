#!/usr/bin/env python3
"""DNS polling script that measures response times for www.google.com and saves results to CSV."""

import argparse
import csv
import socket
import time
from datetime import datetime


def dns_lookup(hostname: str) -> tuple[bool, float, str]:
    """
    Perform a DNS lookup and measure the response time.

    Returns:
        (success, response_time_ms, ip_address_or_error)
    """
    start = time.perf_counter()
    try:
        ip = socket.gethostbyname(hostname)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return True, elapsed_ms, ip
    except socket.gaierror as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return False, elapsed_ms, str(e)


def poll(hostname: str, interval: float, iterations: int, output_file: str) -> None:
    fieldnames = ["timestamp", "hostname", "success", "response_time_ms", "result"]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for i in range(1, iterations + 1):
            timestamp = datetime.now().isoformat()
            success, response_time_ms, result = dns_lookup(hostname)

            row = {
                "timestamp": timestamp,
                "hostname": hostname,
                "success": success,
                "response_time_ms": round(response_time_ms, 3),
                "result": result,
            }
            writer.writerow(row)
            f.flush()

            status = "OK" if success else "FAIL"
            print(
                f"[{i}/{iterations}] {timestamp}  {status}  {response_time_ms:.1f} ms  {result}"
            )

            if i < iterations:
                time.sleep(interval)

    print(f"\nResults saved to {output_file}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Poll DNS for www.google.com and record results to a CSV file."
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Polling interval in seconds between requests (default: 1.0)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        metavar="N",
        help="Number of DNS requests to perform (default: 10)",
    )
    parser.add_argument(
        "--hostname",
        default="www.google.com",
        help="Hostname to resolve (default: www.google.com)",
    )
    parser.add_argument(
        "--output",
        default="dns_results.csv",
        metavar="FILE",
        help="Output CSV file path (default: dns_results.csv)",
    )
    args = parser.parse_args()

    print(f"Polling DNS for '{args.hostname}'")
    print(f"  Iterations : {args.iterations}")
    print(f"  Interval   : {args.interval}s")
    print(f"  Output     : {args.output}")
    print()

    poll(args.hostname, args.interval, args.iterations, args.output)


if __name__ == "__main__":
    main()
