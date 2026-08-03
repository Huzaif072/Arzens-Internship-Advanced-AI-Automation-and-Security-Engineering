#!/usr/bin/env python3
"""
generate_reference_events.py

Generates a synthetic "Week 2 baseline" event set with normal behavior only
(no brute-force burst, no DGA burst), used to produce reference_features.csv
for the quality_validator's drift detection.
"""
import json
import random
from datetime import datetime, timedelta, timezone

random.seed(7)

users = ["alice", "bob", "carol", "dave", "erin"]
hosts = ["vpn-server", "corp-gateway", "app-host-1", "app-host-2"]
normal_domains = ["example.com", "company-portal.com", "mail.google.com", "github.com", "slack.com"]

base_time = datetime(2026, 7, 13, 9, 0, 0, tzinfo=timezone.utc)
events = []

for hour_offset in range(6):
    ts_hour = base_time + timedelta(hours=hour_offset)
    for user in users:
        src_ip = f"192.168.1.{100 + users.index(user)}"
        num_events = random.randint(2, 6)
        for i in range(num_events):
            ts = ts_hour + timedelta(minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            status = "SUCCESS" if random.random() > 0.08 else "FAILURE"
            events.append({
                "timestamp": ts.isoformat().replace("+00:00", "Z"),
                "user": user,
                "source_ip": src_ip,
                "host": random.choice(hosts),
                "status": status,
                "event_type": "AUTH",
            })

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

events.sort(key=lambda e: e["timestamp"])

with open("reference_raw_events.jsonl", "w", encoding="utf-8") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print(f"Wrote {len(events)} baseline events to reference_raw_events.jsonl")
