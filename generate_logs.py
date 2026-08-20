"""
Synthetic SOC log generator -- used to validate the pipeline end-to-end
before migrating to real endpoint telemetry (see hunt_engine.py).

Generates auth, network, and process events with a deliberately planted,
realistic lateral-movement attack scenario buried in the noise.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import json

HOSTS = [f"host-{i:03d}" for i in range(1, 41)]
USERS = [f"user{i}" for i in range(1, 26)] + ["svc_backup", "svc_web", "admin"]


def _rand_ip(rng, internal_prob=0.5):
    if rng.random() < internal_prob:
        return f"10.0.{rng.integers(0,255)}.{rng.integers(0,255)}"
    return f"{rng.integers(1,223)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(0,255)}"


def generate_logs(n=8000, seed=42):
    rng = np.random.default_rng(seed)
    start = datetime(2025, 1, 1)
    rows = []
    event_types = rng.choice(["auth", "network", "process"], size=n, p=[0.35, 0.4, 0.25])

    for i in range(n):
        ts = start + timedelta(seconds=int(rng.integers(0, 7 * 24 * 3600)))
        etype = event_types[i]
        host = rng.choice(HOSTS)
        if etype == "auth":
            success = rng.random() > 0.15
            rows.append({"timestamp": ts.isoformat(), "event_type": "auth", "hostname": host,
                         "user": rng.choice(USERS), "src_ip": _rand_ip(rng, 0.8),
                         "auth_success": bool(success),
                         "detail": "logon success" if success else "logon failure"})
        elif etype == "network":
            dst_port = int(rng.choice([22, 80, 443, 445, 3389, 8080, 53], 1)[0])
            rows.append({"timestamp": ts.isoformat(), "event_type": "network", "hostname": host,
                         "src_ip": _rand_ip(rng, 0.7), "dst_ip": _rand_ip(rng, 0.3),
                         "dst_port": dst_port, "bytes_sent": int(rng.lognormal(8, 2)),
                         "detail": f"connection to port {dst_port}"})
        else:
            proc = rng.choice(["explorer.exe", "chrome.exe", "powershell.exe", "cmd.exe",
                               "svchost.exe", "python.exe", "wmic.exe"])
            rows.append({"timestamp": ts.isoformat(), "event_type": "process", "hostname": host,
                         "user": rng.choice(USERS), "process_name": proc,
                         "detail": f"process launched: {proc}"})

    # plant a hidden lateral-movement attacker scenario (user7)
    attack_start = start + timedelta(days=3, hours=2)
    rows.append({"timestamp": attack_start.isoformat(), "event_type": "auth", "hostname": "host-014",
                 "user": "user7", "src_ip": "10.0.14.9", "auth_success": True, "detail": "logon success"})
    for j, target in enumerate(["host-021", "host-022", "host-025", "host-021"]):
        t = attack_start + timedelta(minutes=5 + j * 2)
        rows.append({"timestamp": t.isoformat(), "event_type": "auth", "hostname": target,
                     "user": "user7", "src_ip": "10.0.14.9", "auth_success": (j == 3),
                     "detail": "logon success" if j == 3 else "logon failure"})
    t = attack_start + timedelta(minutes=16)
    rows.append({"timestamp": t.isoformat(), "event_type": "process", "hostname": "host-021",
                 "user": "user7", "process_name": "powershell.exe", "detail": "process launched: powershell.exe"})
    t = attack_start + timedelta(minutes=18)
    rows.append({"timestamp": t.isoformat(), "event_type": "network", "hostname": "host-021",
                 "src_ip": "10.0.21.4", "dst_ip": "185.220.101.7", "dst_port": 8080,
                 "bytes_sent": 4200, "detail": "connection to port 8080"})

    return rows


if __name__ == "__main__":
    rows = generate_logs()
    with open("logs.json", "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"Generated {len(rows)} events -> logs.json")
