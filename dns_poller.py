#!/usr/bin/env python3
"""DNS polling script driven by a JSON config file.

Reads polling settings from config.json (or a path given via --config),
queries each domain at the specified interval, and writes per-domain CSV files.
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime

import dns.resolver
import dns.reversename


def reverse_lookup(ip: str) -> str:
    """Return the PTR hostname for an IP, or the IP itself if lookup fails."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(rev_name, "PTR", lifetime=2)
        return str(answer[0]).rstrip(".")
    except Exception:
        return ip


def dns_lookup(domain: str, resolver: dns.resolver.Resolver) -> dict:
    """
    Resolve *domain* using *resolver*.

    Returns a dict with keys:
        success, response_time_ms, resolved_ip, dns_server_ip, dns_server_name, error
    """
    start = time.perf_counter()
    try:
        answer = resolver.resolve(domain, "A")
        elapsed_ms = (time.perf_counter() - start) * 1000
        resolved_ip = str(answer[0])
        ns_ip = answer.nameserver  # IP of the server that answered
        ns_name = reverse_lookup(ns_ip)
        return {
            "success": True,
            "response_time_ms": round(elapsed_ms, 3),
            "resolved_ip": resolved_ip,
            "dns_server_ip": ns_ip,
            "dns_server_name": ns_name,
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


def poll_domain(
    domain: str,
    interval: float,
    iterations: int,
    output_file: str,
    resolver: dns.resolver.Resolver,
) -> None:
    fieldnames = [
        "timestamp",
        "domain",
        "success",
        "response_time_ms",
        "resolved_ip",
        "dns_server_ip",
        "dns_server_name",
        "error",
    ]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for i in range(1, iterations + 1):
            timestamp = datetime.now().isoformat()
            result = dns_lookup(domain, resolver)

            row = {"timestamp": timestamp, "domain": domain, **result}
            writer.writerow(row)
            f.flush()

            status = "OK  " if result["success"] else "FAIL"
            ns = result["dns_server_name"] or result["dns_server_ip"] or "-"
            print(
                f"  [{i:>{len(str(iterations))}}/{iterations}] {timestamp}"
                f"  {status}  {result['response_time_ms']:7.1f} ms"
                f"  {result['resolved_ip'] or result['error']}"
                f"  (ns: {ns})"
            )

            if i < iterations:
                time.sleep(interval)

    print(f"  -> saved to {output_file}\n")


def load_config(path: str) -> dict:
    with open(path) as f:
        config = json.load(f)

    missing = [k for k in ("interval", "iterations", "domains") if k not in config]
    if missing:
        sys.exit(f"Config missing required keys: {', '.join(missing)}")
    if not isinstance(config["domains"], list) or not config["domains"]:
        sys.exit("Config 'domains' must be a non-empty list.")

    return config


def build_resolver(config: dict) -> dns.resolver.Resolver:
    """Build a resolver, optionally using a custom DNS server from config."""
    if "dns_server" in config:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [config["dns_server"]]
    else:
        try:
            resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            sys.exit(
                "No system DNS resolver found. "
                "Add a \"dns_server\" key to your config (e.g. \"8.8.8.8\")."
            )
    resolver.lifetime = config.get("timeout", 5.0)
    return resolver


def domain_to_filename(domain: str) -> str:
    """Convert a domain name to a safe CSV filename."""
    safe = domain.replace(":", "_").replace("/", "_").replace("\\", "_")
    return f"{safe}.csv"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Poll DNS for one or more domains and record results to CSV files."
    )
    parser.add_argument(
        "--config",
        default="config.json",
        metavar="FILE",
        help="Path to JSON config file (default: config.json)",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    interval: float = config["interval"]
    iterations: int = config["iterations"]
    domains: list[str] = config["domains"]
    resolver = build_resolver(config)

    print(f"Config : {args.config}")
    print(f"Interval   : {interval}s")
    print(f"Iterations : {iterations}")
    print(f"Domains    : {', '.join(domains)}")
    if "dns_server" in config:
        print(f"DNS server : {config['dns_server']}")
    print()

    for domain in domains:
        output_file = domain_to_filename(domain)
        print(f"Polling '{domain}' -> {output_file}")
        poll_domain(domain, interval, iterations, output_file, resolver)


if __name__ == "__main__":
    main()
