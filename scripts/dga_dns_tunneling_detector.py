"""
dga_dns_tunneling_detector.py

Rule/stat-based detector for:
  1. DGA (Domain Generation Algorithm) domains
  2. DNS tunneling (covert data exfiltration via DNS queries)

No training data needed. Domains are scored using entropy + n-gram
"realness" against a threshold calibrated from public reference lists,
plus a known-bad blocklist for instant matches.

Inputs  (data/raw/):
    Bambenek.csv     - known malicious DGA domains (Bambenek feed)
    Tranco_list.csv  - known benign domains (Tranco top list)

Outputs (docs/):
    dga_detector_report.txt - calibration stats, thresholds, sanity-check results

Usage:
    python scripts/dga_dns_tunneling_detector.py
"""

import os
import sys
import math
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# Assumes this file lives in <project_root>/scripts/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
DOCS_DIR = os.path.join(BASE_DIR, "docs")

BAMBENEK_PATH = os.path.join(DATA_RAW_DIR, "Bambenek.csv")
TRANCO_PATH = os.path.join(DATA_RAW_DIR, "Tranco_list.csv")
REPORT_PATH = os.path.join(DOCS_DIR, "dga_detector_report.txt")

NGRAM_SIZE = 2                  # bigrams
TRANCO_SAMPLE_SIZE = 100_000    # cap for speed; Tranco has 1M+ rows
MIN_DOMAIN_LEN = 4              # domains shorter than this are skipped
ALLOWLIST_SIZE = 10_000         # top-N Tranco domains bypass scoring entirely
ENTROPY_BENIGN_WEIGHT = 1.5      # cost-weight: penalize false positives 1.5x during calibration
                                  # (dialed down from 3.0 — allowlist now handles the major
                                  # false-positive cases, so entropy weighting can be gentler)


# ---------------------------------------------------------------------------
# Tee — mirror print() to console AND report file (same convention as
# analyse_dataset.py, output saved under docs/ per project rule)
# ---------------------------------------------------------------------------
class Tee:
    def __init__(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self.file = open(filepath, "w", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, msg):
        self.stdout.write(msg)
        self.file.write(msg)

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def close(self):
        self.file.close()


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_bambenek(path: str) -> set:
    """Load Bambenek DGA feed -> set of lowercase malicious domains.
    Handles '#' comment lines, no header, extra trailing columns, duplicates.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Bambenek feed not found at: {path}")

    domains = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domain = line.split(",")[0].strip().lower()
            if domain and "." in domain and len(domain) >= MIN_DOMAIN_LEN:
                domains.add(domain)

    if not domains:
        raise ValueError(f"No valid domains parsed from {path} — check file format.")
    return domains


def load_tranco(path: str, sample_size: int = TRANCO_SAMPLE_SIZE) -> list:
    """Load Tranco top-domain list -> list of lowercase benign domains.
    Handles both 'rank,domain' and 'domain'-only formats, with or without header.
    Samples the top N rows for speed on large files.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Tranco list not found at: {path}")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        first_line = f.readline()
    n_cols = len(first_line.strip().split(","))
    col_names = ["rank", "domain"] if n_cols >= 2 else ["domain"]

    df = pd.read_csv(path, header=None, names=col_names, nrows=sample_size,
                      on_bad_lines="skip", engine="python")
    df = df[~df["domain"].astype(str).str.lower().eq("domain")]  # drop stray header row

    domains = df["domain"].dropna().astype(str).str.strip().str.lower().unique().tolist()
    domains = [d for d in domains if d and "." in d and len(d) >= MIN_DOMAIN_LEN]

    if not domains:
        raise ValueError(f"No valid domains parsed from {path} — check file format.")
    return domains


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def compute_entropy(domain: str) -> float:
    """Shannon entropy of the domain string (higher = more random-looking)."""
    s = (domain or "").replace(".", "")
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def build_ngram_model(benign_domains: list, n: int = NGRAM_SIZE) -> dict:
    """Build a smoothed, normalized log-probability n-gram table from
    benign domains' second-level labels (e.g. 'google' from 'google.com').
    """
    counts = defaultdict(int)
    total = 0
    for d in benign_domains:
        core = d.split(".")[0]
        if len(core) < n:
            continue
        for i in range(len(core) - n + 1):
            counts[core[i:i + n]] += 1
            total += 1

    if total == 0:
        raise ValueError("N-gram model is empty — check benign domain list.")

    vocab_size = len(counts)
    model = {gram: math.log((c + 1) / (total + vocab_size)) for gram, c in counts.items()}
    model["__UNSEEN__"] = math.log(1 / (total + vocab_size))  # fallback for unseen n-grams
    return model


def ngram_score(domain: str, model: dict, n: int = NGRAM_SIZE) -> float:
    """Average log-probability of the domain's n-grams under the benign model.
    Closer to 0 = looks like real words. More negative = random-looking.
    """
    core = (domain or "").split(".")[0]
    if len(core) < n:
        return model["__UNSEEN__"]
    scores = [model.get(core[i:i + n], model["__UNSEEN__"]) for i in range(len(core) - n + 1)]
    return sum(scores) / len(scores)


def calibrate_threshold(malicious_scores: list, benign_scores: list,
                         higher_is_malicious: bool = True,
                         benign_weight: float = 1.0):
    """O(n log n) sweep over every candidate score to find the threshold
    that maximizes a (possibly cost-weighted) separation score between
    malicious and benign sets.

    benign_weight > 1.0 penalizes false positives (benign wrongly flagged)
    more heavily than false negatives (malicious missed) — this pushes the
    chosen threshold to be stricter, trading some missed detections for
    fewer false alarms on legitimate domains. It only changes how each
    candidate threshold is scored; nothing is learned or stored.

    Returns (best_threshold, best_plain_accuracy) — the accuracy reported
    is always the unweighted one, for honest comparison across settings.
    """
    mal = sorted(malicious_scores)
    ben = sorted(benign_scores)
    n_mal, n_ben = len(mal), len(ben)
    total = n_mal + n_ben
    candidates = sorted(set(mal) | set(ben))

    best_threshold, best_weighted_score, best_plain_accuracy = candidates[0], 0.0, 0.0
    for t in candidates:
        if higher_is_malicious:
            tp = n_mal - bisect_left(mal, t)
            tn = bisect_left(ben, t)
        else:
            tp = bisect_right(mal, t)
            tn = n_ben - bisect_right(ben, t)

        plain_accuracy = (tp + tn) / total
        weighted_score = (tp + benign_weight * tn) / (n_mal + benign_weight * n_ben)

        if weighted_score > best_weighted_score:
            best_weighted_score = weighted_score
            best_threshold = t
            best_plain_accuracy = plain_accuracy

    return best_threshold, best_plain_accuracy


# ---------------------------------------------------------------------------
# Detector — DGA
# ---------------------------------------------------------------------------
def build_allowlist(benign_domains: list, size: int = ALLOWLIST_SIZE) -> set:
    """Top-N Tranco domains (already rank-ordered), used to bypass scoring
    entirely for well-known legitimate domains. Keep 'size' small and
    conservative — this is a trust shortcut, not a security boundary.
    """
    return set(benign_domains[:size])


def is_allowlisted(domain: str, allowlist_set: set) -> bool:
    """True if the domain, or any of its parent domains, is on the
    allowlist. Handles subdomains: 'static.facebook.com' matches an
    allowlist entry of 'facebook.com'.
    """
    if domain in allowlist_set:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in allowlist_set:
            return True
    return False


def is_dga(domain: str, bambenek_set: set, ngram_model: dict,
           entropy_threshold: float, ngram_threshold: float,
           allowlist_set: set = None) -> dict:
    """Classify a single domain. Order: blocklist match (cheap, certain)
    -> allowlist bypass (cheap, trusted) -> statistical scoring (fallback).
    """
    domain = (domain or "").strip().lower()
    result = {"domain": domain, "flagged": False, "reason": None,
              "entropy": None, "ngram_score": None, "confidence": 0.0}

    if not domain or "." not in domain:
        result["reason"] = "invalid_domain"
        return result

    if domain in bambenek_set:
        result.update(flagged=True, reason="blocklist_match", confidence=1.0)
        return result

    if allowlist_set and is_allowlisted(domain, allowlist_set):
        result["reason"] = "allowlisted"
        return result

    ent = compute_entropy(domain)
    ngs = ngram_score(domain, ngram_model)
    result["entropy"] = round(ent, 3)
    result["ngram_score"] = round(ngs, 3)

    entropy_flag = ent >= entropy_threshold
    ngram_flag = ngs <= ngram_threshold

    if entropy_flag and ngram_flag:
        result.update(flagged=True, reason="entropy+ngram", confidence=0.9)
    elif entropy_flag or ngram_flag:
        result.update(flagged=True, reason="entropy_or_ngram", confidence=0.6)

    return result


# ---------------------------------------------------------------------------
# Detector — DNS tunneling
# (Operates on live DNS query logs, not CICIDS2017 flow data — plug this in
#  once real/simulated DNS query logs are available.)
# ---------------------------------------------------------------------------
def detect_tunneling(query_log: pd.DataFrame, window_seconds: int = 5,
                      query_count_threshold: int = 20,
                      subdomain_len_threshold: int = 30) -> pd.DataFrame:
    """Flag DNS tunneling behavior from a query log.

    Expects columns: ['source_ip', 'domain', 'timestamp'].
    Adds two boolean columns:
      'high_query_rate' - too many queries from one source in a rolling window
      'long_subdomain'  - unusually long subdomain label (data smuggled in the name)
    """
    required_cols = {"source_ip", "domain", "timestamp"}
    missing = required_cols - set(query_log.columns)
    if missing:
        raise ValueError(f"query_log is missing required columns: {missing}")

    df = query_log.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp")

    df["high_query_rate"] = False
    for _, group in df.groupby("source_ip"):
        counts = group.set_index("timestamp")["domain"].rolling(f"{window_seconds}s").count()
        df.loc[group.index, "high_query_rate"] = counts.values >= query_count_threshold

    def longest_label_len(domain):
        if not isinstance(domain, str) or "." not in domain:
            return 0
        labels = domain.split(".")
        subdomain_labels = labels[:-2] if len(labels) > 2 else []
        return max((len(lbl) for lbl in subdomain_labels), default=0)

    df["long_subdomain"] = df["domain"].apply(longest_label_len) >= subdomain_len_threshold
    return df


# ---------------------------------------------------------------------------
# Main — calibrate, evaluate, report
# ---------------------------------------------------------------------------
def main():
    tee = Tee(REPORT_PATH)
    sys.stdout = tee
    try:
        print("=" * 70)
        print("DGA / DNS TUNNELING DETECTOR — CALIBRATION REPORT")
        print("=" * 70)

        print(f"\nLoading Bambenek feed: {BAMBENEK_PATH}")
        malicious_domains = load_bambenek(BAMBENEK_PATH)
        print(f"  -> {len(malicious_domains):,} unique malicious domains loaded")

        print(f"\nLoading Tranco list: {TRANCO_PATH}")
        benign_domains = load_tranco(TRANCO_PATH)
        print(f"  -> {len(benign_domains):,} unique benign domains loaded "
              f"(sampled top {TRANCO_SAMPLE_SIZE:,})")

        print(f"\nBuilding {NGRAM_SIZE}-gram model from benign domains...")
        ngram_model = build_ngram_model(benign_domains)
        print(f"  -> {len(ngram_model) - 1:,} unique {NGRAM_SIZE}-grams learned")

        print("\nScoring reference sets for calibration...")
        malicious_list = list(malicious_domains)
        mal_entropy = [compute_entropy(d) for d in malicious_list]
        ben_entropy = [compute_entropy(d) for d in benign_domains]
        mal_ngram = [ngram_score(d, ngram_model) for d in malicious_list]
        ben_ngram = [ngram_score(d, ngram_model) for d in benign_domains]

        entropy_threshold, entropy_acc = calibrate_threshold(
            mal_entropy, ben_entropy, higher_is_malicious=True,
            benign_weight=ENTROPY_BENIGN_WEIGHT)
        ngram_threshold, ngram_acc = calibrate_threshold(
            mal_ngram, ben_ngram, higher_is_malicious=False)

        print("\n--- Calibration results ---")
        print(f"Entropy threshold : {entropy_threshold:.3f}  (accuracy: {entropy_acc:.2%}, "
              f"benign_weight={ENTROPY_BENIGN_WEIGHT})")
        print(f"N-gram threshold  : {ngram_threshold:.3f}  (accuracy: {ngram_acc:.2%})")

        allowlist_set = build_allowlist(benign_domains, ALLOWLIST_SIZE)
        print(f"\nAllowlist built: top {len(allowlist_set):,} Tranco domains bypass scoring")
        print(f"Malicious entropy  mean/std: {np.mean(mal_entropy):.3f} / {np.std(mal_entropy):.3f}")
        print(f"Benign    entropy  mean/std: {np.mean(ben_entropy):.3f} / {np.std(ben_entropy):.3f}")
        print(f"Malicious ngram    mean/std: {np.mean(mal_ngram):.3f} / {np.std(mal_ngram):.3f}")
        print(f"Benign    ngram    mean/std: {np.mean(ben_ngram):.3f} / {np.std(ben_ngram):.3f}")

        print("\n--- Sanity check on sample domains ---")
        sample_domains = [
            "google.com",                  # obviously benign
            "facebook.com",                # obviously benign
            "xk29fj2q8zpmw1n.net",         # obviously DGA-looking (synthetic)
            malicious_list[0],             # real Bambenek domain -> blocklist hit
            "",                            # edge case: empty string
            "no-dots-here",                # edge case: no TLD
        ]
        for d in sample_domains:
            print(f"  {is_dga(d, malicious_domains, ngram_model, entropy_threshold, ngram_threshold, allowlist_set)}")

        print("\nDone. Hardcode the thresholds above into is_dga() calls for production use.")

    finally:
        sys.stdout = tee.stdout
        tee.close()

    print(f"Report saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()