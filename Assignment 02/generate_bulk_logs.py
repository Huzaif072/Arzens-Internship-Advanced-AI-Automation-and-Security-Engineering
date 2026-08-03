"""
generate_bulk_logs.py — Synthetic Log Generator for Stress Testing
Generates a mixed log file of 5,000+ records across all three formats.

Usage:
    python generate_bulk_logs.py --count 5000 --output bulk_logs_mixed.txt
    python generate_bulk_logs.py --count 2000 --firewall fw.csv --auth auth.txt --dns dns.txt
"""

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ── Seed data ──────────────────────────────────────────────────────────────────

INTERNAL_IPS = [f"10.0.{b}.{c}" for b in range(0, 5) for c in range(1, 51)]
INTERNAL_IPS += [f"192.168.{b}.{c}" for b in range(0, 3) for c in range(1, 51)]
EXTERNAL_IPS = [
    "203.0.113.45", "198.51.100.10", "185.220.101.34", "45.33.32.156",
    "91.108.4.0", "103.251.167.10", "1.1.1.1", "8.8.8.8", "104.244.42.129",
    "151.101.65.69", "172.217.3.110", "13.107.4.50", "52.114.77.33",
]

FIREWALL_ACTIONS = ["ALLOW", "ALLOW", "ALLOW", "DENY", "DENY"]
PORTS = [22, 80, 443, 53, 3389, 8080, 5432, 6379, 25, 21, 23, 3306]

USERNAMES = [
    "alice_web", "bob_dev", "charlie_ops", "dave_admin", "eve_analyst",
    "frank_hr", "grace_eng", "hank_devops", "ivan_support", "judy_ciso",
    "root", "admin", "unknown_user", "svc_backup", "svc_monitor",
]
HOSTS = ["corporate-vpn", "office-wifi", "remote-access", "vpn-gateway",
         "mobile-hotspot", "external-network"]
AUTH_STATUSES = ["SUCCESS", "SUCCESS", "SUCCESS", "FAILURE", "FAILURE"]

DOMAINS_LEGIT = ["google.com", "github.com", "stackoverflow.com", "pypi.org",
                 "cloudflare.com", "amazonaws.com", "slack.com", "microsoft.com"]
DOMAINS_SUSPICIOUS = ["suspicious.example.com", "malware-c2.ru", "cryptominer-pool.xyz",
                       "phishing-site.tk", "botnet-callback.net", "fast-flux-domain.cc",
                       "dga-generated-abc123.pw"]
DNS_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME"]
DNS_RESPONSES = ["NOERROR", "NOERROR", "NOERROR", "NXDOMAIN", "NXDOMAIN", "SERVFAIL", "REFUSED"]


def random_ts(base: datetime, jitter_secs: int = 86400) -> str:
    delta = timedelta(seconds=random.randint(0, jitter_secs))
    dt = base + delta
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def gen_firewall(base_ts: datetime) -> str:
    src = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    port = random.choice(PORTS)
    action = random.choice(FIREWALL_ACTIONS)
    if action == "ALLOW":
        byt = random.randint(64, 10_000_000)
    else:
        byt = random.randint(0, 1024)
    ts = random_ts(base_ts)
    return f"{ts},{src},{dst},{port},{action},{byt}"


def gen_auth(base_ts: datetime) -> str:
    ts_dt = datetime.strptime(random_ts(base_ts), "%Y-%m-%dT%H:%M:%SZ")
    ts = ts_dt.strftime("%Y-%m-%d %H:%M:%S")
    user = random.choice(USERNAMES)
    host = random.choice(HOSTS)
    status = random.choice(AUTH_STATUSES)
    src = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    return f"{ts} {user} {host} {status} {src}"


def gen_dns(base_ts: datetime) -> str:
    ts = random_ts(base_ts)
    client = random.choice(INTERNAL_IPS)
    domain_pool = DOMAINS_LEGIT * 3 + DOMAINS_SUSPICIOUS
    domain = random.choice(domain_pool)
    qtype = random.choice(DNS_TYPES)
    response = random.choice(DNS_RESPONSES)
    return f"query_time={ts}|client={client}|domain={domain}|type={qtype}|response={response}"


# ── Generator ──────────────────────────────────────────────────────────────────

def generate_mixed(count: int, base_ts: datetime) -> list[str]:
    """
    Generate *count* lines, distributed roughly evenly across three formats.
    Returns raw lines with a leading format tag comment stripped; each line is
    pure log data in its native format.
    """
    lines: list[str] = []
    per_format = count // 3
    remainder = count - (per_format * 3)

    generators = [gen_firewall, gen_auth, gen_dns]
    counts = [per_format, per_format, per_format + remainder]

    for gen, n in zip(generators, counts):
        for _ in range(n):
            lines.append(gen(base_ts))

    random.shuffle(lines)
    return lines


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Synthetic mixed log generator for stress testing")
    p.add_argument("--count", type=int, default=5000,
                   help="Total number of log records to generate (default: 5000)")
    p.add_argument("--output", default="bulk_logs_mixed.txt",
                   help="Output file path (default: bulk_logs_mixed.txt)")
    p.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = p.parse_args(argv)

    random.seed(args.seed)
    base_ts = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    print(f"Generating {args.count} synthetic log records …")
    lines = generate_mixed(args.count, base_ts)

    out = Path(args.output)
    with out.open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")

    print(f"Done. Wrote {len(lines)} lines to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
