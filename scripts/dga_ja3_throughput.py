import time
import random
import string
import csv
from datetime import datetime, timedelta

from detector_interfaces import classify_dns_query, classify_tls_session, BAMBENEK_PATH
from ja3_detector import BLOCKLIST_PATH as JA3_BLOCKLIST_PATH

# -----------------------------------------------------------------
# 1. Build a representative domain sample: 3 branches, not just one
# -----------------------------------------------------------------
def load_bambenek_domains(path, n=200):
    domains = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            d = line.split(",")[0].strip().lower()
            if d and "." in d:
                domains.append(d)
            if len(domains) >= n:
                break
    return domains

def random_novel_domain():
    core = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 20)))
    return f"{core}.com"

blocklist_domains = load_bambenek_domains(BAMBENEK_PATH, n=100)          # branch: blocklist_match
allowlisted_domains = ["google.com", "facebook.com", "amazon.com",        # branch: allowlisted
                        "microsoft.com", "wikipedia.org"] * 20
novel_domains = [random_novel_domain() for _ in range(100)]              # branch: entropy+ngram fallback

domain_sample = blocklist_domains + allowlisted_domains + novel_domains
random.shuffle(domain_sample)

FAKE_IPS = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(30)]
base_time = datetime.utcnow()

dns_calls = [
    (d, "A", (base_time + timedelta(milliseconds=i)).isoformat(), random.choice(FAKE_IPS))
    for i, d in enumerate(domain_sample)
]

# -----------------------------------------------------------------
# 2. JA3 sample: blocklist hits + valid-format benign hashes
# -----------------------------------------------------------------
def load_ja3_hashes(path, n=100):
    hashes = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        idx = next(i for i, c in enumerate(header) if "ja3" in c.lower() or "hash" in c.lower())
        for row in reader:
            if row and row[idx].strip():
                hashes.append(row[idx].strip().lower())
            if len(hashes) >= n:
                break
    return hashes

def random_valid_ja3():
    return "".join(random.choices("0123456789abcdef", k=32))

ja3_blocklist_hashes = load_ja3_hashes(JA3_BLOCKLIST_PATH, n=100)
ja3_benign_hashes = [random_valid_ja3() for _ in range(100)]
ja3_sample = ja3_blocklist_hashes + ja3_benign_hashes
random.shuffle(ja3_sample)

ja3_calls = [
    (fp, "tls", "client", (base_time + timedelta(milliseconds=i)).isoformat(), random.choice(FAKE_IPS))
    for i, fp in enumerate(ja3_sample)
]

# -----------------------------------------------------------------
# 3. Warm-up — critical here: first classify_dns_query() call pays
#    the ONE-TIME Bambenek+Tranco load + n-gram build cost. Must not
#    land inside the timed loop.
# -----------------------------------------------------------------
classify_dns_query(*dns_calls[0])   # pays the one-time calibration cost here, discarded
classify_tls_session(*ja3_calls[0])

# -----------------------------------------------------------------
# 4. Timed loops
# -----------------------------------------------------------------
dga_latencies = []
for args in dns_calls:
    t0 = time.perf_counter()
    classify_dns_query(*args)
    dga_latencies.append(time.perf_counter() - t0)

ja3_latencies = []
for args in ja3_calls:
    t0 = time.perf_counter()
    classify_tls_session(*args)
    ja3_latencies.append(time.perf_counter() - t0)

# -----------------------------------------------------------------
# 5. Report
# -----------------------------------------------------------------
import numpy as np

def report(name, latencies):
    arr = np.array(latencies)
    print(f"{name}: p50={np.percentile(arr,50)*1e6:.1f}µs  "
          f"p95={np.percentile(arr,95)*1e6:.1f}µs  "
          f"p99={np.percentile(arr,99)*1e6:.1f}µs  "
          f"throughput={len(arr)/arr.sum():.1f} flows/sec")

report("DGA/DNS", dga_latencies)
report("JA3", ja3_latencies)