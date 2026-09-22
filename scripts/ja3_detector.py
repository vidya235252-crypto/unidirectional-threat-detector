import hashlib
import os
import sys
import csv
import re

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
DOCS_DIR = os.path.join(BASE_DIR, "docs")

BLOCKLIST_PATH = os.path.join(DATA_RAW_DIR, "ja3_fingerprints.csv")
REPORT_PATH = os.path.join(DOCS_DIR, "tls_ja3_detector_report.txt")

# Candidate column-name fragments for the hash column, checked as
# substrings against the REAL CSV header row (not banner/comment text).
JA3_HASH_CANDIDATES = ["ja3_md5", "ja3", "hash", "fingerprint"]

# A JA3/JA3S hash is always an MD5 digest: 32 lowercase hex characters.
JA3_HASH_PATTERN = re.compile(r"^[a-f0-9]{32}$")

# GREASE values (RFC 8701) — TLS clients insert these on purpose to test
# middlebox tolerance for unknown values. They're randomized per connection,
# so they MUST be stripped before hashing or every session looks unique.
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


# ---------------------------------------------------------------------------
# Tee — mirror print() to console AND report file (project convention;
# output saved under docs/, per the code -> scripts/, output -> docs/ rule)
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
def load_fingerprint_blocklist(filepath: str) -> set[str]:
    """Load JA3 hashes from a plain CSV with a real header row (no banner
    comments to skip — e.g. 'ja3_md5,Firstseen,Lastseen,Listingreason').
    Validates every loaded value against the JA3 hash shape before trusting
    the load, so a coincidentally 'successful' but wrong parse can't happen
    silently.
    """
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)

        hash_col_idx = None
        matched_col_name = None
        for idx, col in enumerate(header):
            col_lower = col.strip().lower()
            if any(cand in col_lower for cand in JA3_HASH_CANDIDATES):
                hash_col_idx = idx
                matched_col_name = col.strip()
                break

        if hash_col_idx is None:
            raise ValueError(f"No JA3 hash column found in header: {header}")

        hashes = set()
        for row in reader:
            if not row or hash_col_idx >= len(row):
                continue
            # abuse.ch appends a footer comment line too, e.g.
            # "# END (97) entries" — same class of noise as the header
            # banner, just at the bottom of the file instead of the top.
            if row[0].strip().startswith("#"):
                continue
            value = row[hash_col_idx].strip()
            if value:
                hashes.add(value)

    if not hashes:
        raise ValueError(f"No fingerprint values loaded from column '{matched_col_name}'.")

    bad = [h for h in hashes if not JA3_HASH_PATTERN.fullmatch(h)]
    if bad:
        raise ValueError(
            f"{len(bad)} loaded values from column '{matched_col_name}' "
            f"fail JA3 hash format (expected 32 hex chars), e.g. {bad[:3]}"
        )

    sample = next(iter(hashes))
    print(f"  -> {len(hashes):,} known-bad fingerprints loaded")
    print(f"  -> matched hash column: '{matched_col_name}' (column index {hash_col_idx})")
    print(f"  -> sample loaded value: '{sample}'")

    return hashes


# ---------------------------------------------------------------------------
# GREASE filtering
# ---------------------------------------------------------------------------
def strip_grease(values) -> list:
    """Remove GREASE values from a list of integer cipher/extension/curve IDs."""
    return [v for v in (values or []) if v not in GREASE_VALUES]


# ---------------------------------------------------------------------------
# JA3 / JA3S computation
# ---------------------------------------------------------------------------
def compute_ja3(tls_version: int, cipher_suites: list, extensions: list,
                 elliptic_curves: list, ec_point_formats: list) -> str:
    """Compute the JA3 (client) fingerprint from a ClientHello's fields.
    Fields are kept in handshake order (not sorted) — order is part of
    the fingerprint. Empty lists are valid and produce an empty subfield.
    """
    ciphers = strip_grease(cipher_suites)
    exts = strip_grease(extensions)
    curves = strip_grease(elliptic_curves)
    formats = ec_point_formats or []  # point formats are not GREASE-able

    ja3_string = ",".join([
        str(tls_version),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in exts),
        "-".join(str(c) for c in curves),
        "-".join(str(f) for f in formats),
    ])
    return hashlib.md5(ja3_string.encode("utf-8")).hexdigest()


def compute_ja3s(tls_version: int, chosen_cipher: int, extensions: list) -> str:
    """Compute the JA3S (server) fingerprint from a ServerHello's fields.
    Simpler than JA3: version + the single chosen cipher + extensions only.
    """
    exts = strip_grease(extensions)
    ja3s_string = ",".join([
        str(tls_version),
        str(chosen_cipher) if chosen_cipher is not None else "",
        "-".join(str(e) for e in exts),
    ])
    return hashlib.md5(ja3s_string.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
def is_malicious_fingerprint(fingerprint_hash: str, blocklist_set: set) -> bool:
    """Case-insensitive membership check against the blocklist."""
    return (fingerprint_hash or "").lower() in blocklist_set


def analyze_session(session: dict, blocklist_set: set) -> dict:
    """Classify one handshake session (TLS or QUIC — QUIC carries a real
    TLS 1.3 ClientHello internally, so the same fingerprinting applies).

    Expected session dict shape:
        {
          "transport": "tls" | "quic",
          "role": "client" | "server",
          "tls_version": int,
          "cipher_suites": [int, ...]   # client only
          "chosen_cipher": int          # server only
          "extensions": [int, ...],
          "elliptic_curves": [int, ...] # client only
          "ec_point_formats": [int, ...]# client only
        }
    """
    result = {"transport": None, "role": None, "fingerprint": None,
              "flagged": False, "reason": None}

    if not isinstance(session, dict):
        result["reason"] = "invalid_session"
        return result

    transport = session.get("transport")
    role = session.get("role")
    result["transport"], result["role"] = transport, role

    if transport not in ("tls", "quic") or role not in ("client", "server"):
        result["reason"] = "invalid_session"
        return result

    tls_version = session.get("tls_version")
    if tls_version is None:
        result["reason"] = "missing_tls_version"
        return result

    if role == "client":
        fp = compute_ja3(
            tls_version,
            session.get("cipher_suites", []),
            session.get("extensions", []),
            session.get("elliptic_curves", []),
            session.get("ec_point_formats", []),
        )
    else:
        fp = compute_ja3s(
            tls_version,
            session.get("chosen_cipher"),
            session.get("extensions", []),
        )

    result["fingerprint"] = fp
    if is_malicious_fingerprint(fp, blocklist_set):
        result.update(flagged=True, reason="blocklist_match")
    else:
        result["reason"] = "clean"

    return result


# ---------------------------------------------------------------------------
# Main — load, sanity-check, report
# ---------------------------------------------------------------------------
def main():
    tee = Tee(REPORT_PATH)
    sys.stdout = tee
    try:
        print("=" * 70)
        print("TLS/QUIC JA3 FINGERPRINT DETECTOR — REPORT")
        print("=" * 70)

        print(f"\nLoading fingerprint blocklist: {BLOCKLIST_PATH}")
        blocklist = load_fingerprint_blocklist(BLOCKLIST_PATH)

        print("\n--- Sanity check on sample sessions ---")

        # 1. Normal-looking Chrome-like TLS ClientHello (should NOT flag)
        normal_client = {
            "transport": "tls", "role": "client", "tls_version": 771,
            "cipher_suites": [0x0A0A, 4865, 4866, 4867, 49195, 49199],  # includes GREASE
            "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 51, 43, 13],
            "elliptic_curves": [0x0A0A, 29, 23, 24],
            "ec_point_formats": [0],
        }
        print(f"  {analyze_session(normal_client, blocklist)}")

        # 2. A fingerprint taken directly FROM the loaded blocklist — proves
        #    the match path works without guessing real malware field values
        known_bad_hash = next(iter(blocklist))
        print(f"  known-bad-hash direct check: "
              f"{{'fingerprint': '{known_bad_hash}', "
              f"'flagged': {is_malicious_fingerprint(known_bad_hash, blocklist)}}}")

        # 3. QUIC session reusing the same JA3 logic (should NOT flag)
        quic_client = {
            "transport": "quic", "role": "client", "tls_version": 772,
            "cipher_suites": [4865, 4866, 4867],
            "extensions": [0, 10, 16, 43, 51],
            "elliptic_curves": [29, 23],
            "ec_point_formats": [0],
        }
        print(f"  {analyze_session(quic_client, blocklist)}")

        # 4. Server-side JA3S (should NOT flag)
        normal_server = {
            "transport": "tls", "role": "server", "tls_version": 771,
            "chosen_cipher": 4865,
            "extensions": [0, 23, 65281, 11],
        }
        print(f"  {analyze_session(normal_server, blocklist)}")

        # --- Edge cases ---
        print("\n--- Edge cases ---")
        print(f"  empty cipher list : {analyze_session({'transport': 'tls', 'role': 'client', 'tls_version': 771, 'cipher_suites': [], 'extensions': [], 'elliptic_curves': [], 'ec_point_formats': []}, blocklist)}")
        print(f"  all-GREASE ciphers: {analyze_session({'transport': 'tls', 'role': 'client', 'tls_version': 771, 'cipher_suites': [0x0A0A, 0x1A1A], 'extensions': [], 'elliptic_curves': [], 'ec_point_formats': []}, blocklist)}")
        print(f"  missing tls_version: {analyze_session({'transport': 'tls', 'role': 'client', 'cipher_suites': [4865]}, blocklist)}")
        print(f"  invalid transport : {analyze_session({'transport': 'http', 'role': 'client', 'tls_version': 771}, blocklist)}")
        print(f"  not a dict at all : {analyze_session('not_a_session', blocklist)}")
        print(f"  empty dict        : {analyze_session({}, blocklist)}")

        print(f"\nDone. blocklist matching is pure lookup — refresh "
              f"{os.path.basename(BLOCKLIST_PATH)} regularly since coverage "
              f"(not tuning) determines accuracy here.")

    finally:
        sys.stdout = tee.stdout
        tee.close()

    print(f"Report saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()