#!/usr/bin/env python3
"""
generate_sample_events.py

One-off helper to generate a synthetic sample_raw_events.jsonl covering
AUTH, NETWORK, and DNS events across several users/hosts and a few hours.
Not part of the graded deliverables list, but kept for reproducibility.
"""
import json
import random
from datetime import datetime, timedelta, timezone

random.seed(42)

users = ["alice", "bob", "carol", "dave", "erin"]
hosts = ["vpn-server", "corp-gateway", "app-host-1", "app-host-2"]
normal_domains = ["example.com", "company-portal.com", "mail.google.com", "github.com", "slack.com"]
dga_domains = ["xk3q9fjzo.net", "a8f2kdle9z.com", "qz93mfoqle.ru", "vb7x2npqal.top"]

base_time = datetime(2026, 7, 20, 9, 0, 0, tzinfo=timezone.utc)
events = []

# AUTH events: several per user across a spread of hours, including a
# brute-force burst for "carol" and a normal pattern for everyone else.
for hour_offset in range(6):
    ts_hour = base_time + timedelta(hours=hour_offset)
    for user in users:
        src_ip = f"192.168.1.{100 + users.index(user)}"
        num_events = random.randint(2, 6)
        for i in range(num_events):
            ts = ts_hour + timedelta(minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            status = "SUCCESS" if random.random() > 0.15 else "FAILURE"
            events.append({
                "timestamp": ts.isoformat().replace("+00:00", "Z"),
                "user": user,
                "source_ip": src_ip,
                "host": random.choice(hosts),
                "status": status,
                "event_type": "AUTH",
            })

# Brute-force burst for "carol" in hour 2 (many failures in a short span).
burst_hour = base_time + timedelta(hours=2)
for i in range(12):
    ts = burst_hour + timedelta(minutes=i, seconds=random.randint(0, 30))
    events.append({
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "user": "carol",
        "source_ip": "203.0.113.55",
        "host": "vpn-server",
        "status": "FAILURE",
        "event_type": "AUTH",
    })

# NETWORK events: normal traffic plus a couple of large transfers.
for hour_offset in range(6):
    ts_hour = base_time + timedelta(hours=hour_offset)
    for user in users:
        src_ip = f"192.168.1.{100 + users.index(user)}"
        num_events = random.randint(3, 8)
        for i in range(num_events):
            ts = ts_hour + timedelta(minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            byte_count = random.randint(500, 50000)
            events.append({
                "timestamp": ts.isoformat().replace("+00:00", "Z"),
                "source_ip": src_ip,
                "dest_ip": f"10.0.0.{random.randint(1, 254)}",
                "port": random.choice([443, 80, 22, 8080, 3389]),
                "bytes": byte_count,
                "protocol": random.choice(["TCP", "UDP"]),
                "event_type": "NETWORK",
            })

# One large-transfer outlier (possible exfiltration).
events.append({
    "timestamp": (base_time + timedelta(hours=3, minutes=10)).isoformat().replace("+00:00", "Z"),
    "source_ip": "192.168.1.101",
    "dest_ip": "198.51.100.9",
    "port": 443,
    "bytes": 5_200_000,
    "protocol": "TCP",
    "event_type": "NETWORK",
})

# DNS events: normal domains plus a batch of DGA-looking domains from one host.
for hour_offset in range(6):
    ts_hour = base_time + timedelta(hours=hour_offset)
    for user in users:
        src_ip = f"192.168.1.{100 + users.index(user)}"
        num_events = random.randint(2, 5)
        for i in range(num_events):
            ts = ts_hour + timedelta(minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            domain = random.choice(normal_domains)
            events.append({
                "timestamp": ts.isoformat().replace("+00:00", "Z"),
                "client_ip": src_ip,
                "query_domain": domain,
                "record_type": "A",
                "response": f"93.184.{random.randint(0,255)}.{random.randint(1,254)}",
                "event_type": "DNS",
            })

# DGA burst from bob's IP (possible malware beaconing).
dga_hour = base_time + timedelta(hours=4)
for i in range(8):
    ts = dga_hour + timedelta(minutes=i * 2)
    events.append({
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "client_ip": "192.168.1.101",
        "query_domain": random.choice(dga_domains),
        "record_type": "A",
        "response": "NXDOMAIN",
        "event_type": "DNS",
    })

events.sort(key=lambda e: e["timestamp"])

with open("sample_raw_events.jsonl", "w", encoding="utf-8") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print(f"Wrote {len(events)} events to sample_raw_events.jsonl")
