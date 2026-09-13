import json
import random
from datetime import datetime, timedelta

OUT_DIR = "data/scenarios"


def write_jsonl(filename, packets):
    path = f"{OUT_DIR}/{filename}"
    with open(path, "w") as f:
        for p in packets:
            f.write(json.dumps(p) + "\n")
    print(f"wrote {len(packets)} packets to {path}")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_benign():
    start = datetime(2026, 9, 11, 9, 0, 0)
    packets = []
    t = start
    for i in range(20):
        t += timedelta(milliseconds=random.randint(80, 400))
        packets.append({
            "timestamp": iso(t),
            "src_ip": "10.0.0.5",
            "dst_ip": "93.184.216.34",
            "src_port": 51000,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_size": random.randint(200, 1400),
            "syn_flag": i == 0
        })
    return packets


def generate_port_scan():
    start = datetime(2026, 9, 11, 9, 30, 0)
    packets = []
    t = start
    for port in range(1, 41):
        t += timedelta(milliseconds=random.randint(5, 20))
        packets.append({
            "timestamp": iso(t),
            "src_ip": "10.0.0.77",
            "dst_ip": "10.0.0.9",
            "src_port": 49000,
            "dst_port": port,
            "protocol": "TCP",
            "packet_size": 60,
            "syn_flag": True
        })
    return packets


def generate_syn_flood():
    start = datetime(2026, 9, 11, 10, 0, 0)
    packets = []
    t = start
    for i in range(500):
        t += timedelta(milliseconds=random.randint(1, 4))
        packets.append({
            "timestamp": iso(t),
            "src_ip": f"172.16.0.{random.randint(2, 254)}",
            "dst_ip": "10.0.0.20",
            "src_port": random.randint(1024, 65000),
            "dst_port": 80,
            "protocol": "TCP",
            "packet_size": 60,
            "syn_flag": True
        })
    return packets


def generate_c2_beaconing():
    start = datetime(2026, 9, 11, 11, 0, 0)
    packets = []
    t = start
    for i in range(12):
        t += timedelta(seconds=30 + random.uniform(-0.3, 0.3))
        packets.append({
            "timestamp": iso(t),
            "src_ip": "10.0.0.15",
            "dst_ip": "198.51.100.23",
            "src_port": 52000,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_size": random.randint(280, 320),
            "syn_flag": i == 0
        })
    return packets


if __name__ == "__main__":
    write_jsonl("benign.jsonl", generate_benign())
    write_jsonl("port_scan.jsonl", generate_port_scan())
    write_jsonl("syn_flood.jsonl", generate_syn_flood())
    write_jsonl("c2_beaconing.jsonl", generate_c2_beaconing())