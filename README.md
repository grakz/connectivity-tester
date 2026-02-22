# Connectivity Tester

A lightweight Python polling tool that continuously monitors network connectivity by running DNS queries, ICMP pings, and optional HTTP(S) checks against a configurable list of targets. All targets are polled concurrently, and results are written to per-target CSV files for easy analysis.

## Features

- **DNS polling** — resolves domains via a configurable resolver, records response time, resolved IP, and answering nameserver
- **HTTP(S) check** — optional follow-up GET request after each DNS query; checks for a 200 status and measures response time independently
- **ICMP ping** — sends ICMP echo requests to any IP address or hostname
- **Concurrent polling** — all targets run in parallel threads, so the interval applies uniformly across every target
- **Per-target CSV output** — one CSV file per domain or host, flushed after every poll so data is never lost mid-run
- **Live summary CSV** — `summary.csv` is rewritten after every poll cycle with aggregate stats (totals, error rate, avg/min/max response times) across all targets

## Requirements

Python 3.10+ and the following packages (see `requirements.txt`):

```
dnspython>=2.4
icmplib>=3.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

> **Note:** ICMP ping uses raw sockets when run as root and falls back to unprivileged UDP sockets otherwise. Both modes work without any extra configuration.

## Quick start

```bash
python3 dns_poller.py
# or point at a custom config:
python3 dns_poller.py --config my_config.json
```

## Configuration

All settings live in a single JSON file (`config.json` by default).

```json
{
  "interval": 5.0,
  "iterations": 10,
  "timeout": 5.0,
  "dns_server": "8.8.8.8",
  "http_check": true,
  "domains": [
    "www.google.com",
    "www.github.com"
  ],
  "ping_hosts": [
    "8.8.8.8",
    "1.1.1.1",
    "2606:4700:4700::1111"
  ]
}
```

### Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `interval` | float | yes | — | Seconds to wait between successive polls for each target |
| `iterations` | int | yes | — | Total number of poll cycles to run before exiting |
| `timeout` | float | no | `5.0` | Per-request timeout in seconds (applies to DNS, HTTP, and ping) |
| `dns_server` | string | no | system resolver | IP address of the DNS server to query (e.g. `"8.8.8.8"`) |
| `http_check` | bool | no | `false` | When `true`, follows each DNS query with an HTTP(S) GET request |
| `domains` | array of strings | no* | `[]` | Domain names to resolve via DNS |
| `ping_hosts` | array of strings | no* | `[]` | IPv4 addresses, IPv6 addresses, or hostnames to ICMP ping |

\* At least one of `domains` or `ping_hosts` must be present.

## Output files

The tool writes one CSV file per target into the current working directory. Files are created (or overwritten) at startup and flushed after every row.

### DNS — `dns_<domain>.csv`

Written for every entry in `domains`. When `http_check` is `false`, the file has 8 columns. When `http_check` is `true`, 4 additional HTTP columns are appended.

| Column | Description |
|---|---|
| `timestamp` | ISO 8601 timestamp of the poll |
| `domain` | Domain that was queried |
| `success` | `True` if the DNS query returned an answer |
| `response_time_ms` | DNS query round-trip time in milliseconds |
| `resolved_ip` | First A record returned |
| `dns_server_ip` | IP of the nameserver that answered |
| `dns_server_name` | PTR hostname of the nameserver (or its IP if PTR is unavailable) |
| `error` | Error message if the query failed; empty otherwise |
| `http_success` | *(http_check only)* `True` when the HTTP status code is exactly 200 |
| `http_status_code` | *(http_check only)* HTTP status code (e.g. `200`, `404`); `0` if no response was received |
| `http_response_time_ms` | *(http_check only)* Time from sending the request to receiving response headers |
| `http_error` | *(http_check only)* Error message if the request failed; empty otherwise |

### ICMP ping — `ping_<host>.csv`

Written for every entry in `ping_hosts`. IPv6 colons in filenames are replaced with underscores (e.g. `ping___1.csv` for `::1`).

| Column | Description |
|---|---|
| `timestamp` | ISO 8601 timestamp of the poll |
| `host` | Address or hostname that was pinged |
| `success` | `True` if at least one ICMP reply was received |
| `response_time_ms` | Round-trip time in milliseconds; `0` if no reply |
| `packets_sent` | Number of ICMP packets sent (always `1`) |
| `packets_received` | Number of ICMP replies received (`0` or `1`) |
| `error` | Error message if the ping failed; empty otherwise |

## HTTP check behaviour

When `http_check` is `true` the tool attempts an `HTTPS` GET to `https://<domain>`. If the HTTPS attempt fails due to an SSL or connection-level error (not an HTTP error like 4xx or 5xx), it automatically retries with plain `HTTP`. The DNS and HTTP measurements are fully independent:

- A DNS failure does **not** prevent the HTTP check from running.
- The HTTP response time covers the full round trip from sending the request to receiving the response headers (body is not downloaded).
- `http_success` is `True` only when the final HTTP status code is exactly `200`.

## Summary file — `summary.csv`

Always written to the current working directory. It contains one row per (target, check type) combination and is fully rewritten and flushed after **every individual poll result**, so it is always up to date even during a long run.

| Column | Description |
|---|---|
| `target` | Domain name or host address |
| `type` | `dns`, `http`, or `ping` |
| `total` | Total polls completed so far |
| `successes` | Polls that succeeded |
| `errors` | Polls that failed |
| `error_rate_pct` | `errors / total × 100`, rounded to one decimal place |
| `avg_response_time_ms` | Mean response time across all timed measurements |
| `min_response_time_ms` | Fastest recorded response time |
| `max_response_time_ms` | Slowest recorded response time |

Rows appear in the same order as targets are declared in the config (`domains` first, then `ping_hosts`). For domains with `http_check` enabled, the `dns` row is immediately followed by its `http` row.

Response times of exactly `0 ms` (e.g. a ping that received no reply) are excluded from the timing statistics so they don't distort the averages.

## Command-line options

```
usage: dns_poller.py [-h] [--config FILE]

options:
  -h, --help     show this help message and exit
  --config FILE  Path to JSON config file (default: config.json)
```

## Example console output

```
Config     : config.json
Interval   : 5.0s  |  Iterations: 10  |  Timeout: 5.0s
DNS domains: www.google.com, www.github.com  (+HTTP check)
DNS server : 8.8.8.8
Ping hosts : 8.8.8.8, 1.1.1.1

  [ping 8.8.8.8   1/10]  2026-02-22T10:00:00.1  OK      12.3 ms
  [ping 1.1.1.1   1/10]  2026-02-22T10:00:00.1  OK       9.8 ms
  [dns  www.google.com  1/10]  2026-02-22T10:00:00.1  DNS:OK    18.4 ms  142.250.80.68  (ns: dns.google)  |  HTTP:OK    87.2 ms  [200]
  [dns  www.github.com  1/10]  2026-02-22T10:00:00.1  DNS:OK    22.1 ms  140.82.121.4   (ns: ns1.github.com)  |  HTTP:OK   143.6 ms  [200]
```
