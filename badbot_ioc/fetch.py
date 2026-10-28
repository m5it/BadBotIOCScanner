"""
Fetch malware hashes from APIs -> save to harddisk DB
- MalwareBazaar (abuse.ch) - now requires API key (set MB_API_KEY env)
- Fallback: MalwareBazaar CSV export via ThreatFox or local demo
"""
import json
import os
from pathlib import Path
import requests

MB_API = "https://mb-api.abuse.ch/api/v1/"
MB_CSV_FALLBACK = "https://threatfox.abuse.ch/export/json/recent/"  # ThreatFox is successor, also free
DEFAULT_DB_JSON = Path("db/hashes.json")
DEFAULT_DB_SQLITE = Path("db/hashes.db")
RAW_DIR = Path("db")

def fetch_malwarebazaar(limit: int = 100, tag: str = None, query: str = "get_recent", selector: str = "time") -> list:
    """
    Fetch from MalwareBazaar. Now requires API key via MB_API_KEY env var.
    If no key, tries ThreatFox fallback or returns demo.
    """
    api_key = os.getenv("MB_API_KEY") or os.getenv("ABUSECH_API_KEY")
    headers = {"User-Agent": "BadBotIOCScanner/0.1"}
    if api_key:
        headers["Auth-Key"] = api_key

    payload = {"query": query}
    if query == "get_recent":
        payload["selector"] = selector
    elif query == "get_taginfo":
        payload["tag"] = tag or "exe"
        payload["limit"] = limit
    elif tag:
        payload["tag"] = tag
        payload["limit"] = limit
        payload["query"] = "get_taginfo"

    # Try MalwareBazaar API first (needs key since 2024)
    if api_key:
        try:
            r = requests.post(MB_API, data=payload, headers=headers, timeout=30)
            if r.status_code == 200:
                data = r.json()
                RAW_DIR.mkdir(parents=True, exist_ok=True)
                (RAW_DIR / "mb_raw.json").write_text(json.dumps(data, indent=2))
                print(f"[+] Saved raw API to harddisk {RAW_DIR}/mb_raw.json ({len(r.text)} bytes)")
                if data.get("query_status") == "ok" and "data" in data:
                    entries = data["data"]
                    return entries[:limit] if limit else entries
            else:
                print(f"[!] MalwareBazaar HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            print(f"[!] MalwareBazaar fetch failed: {e}")

    # Fallback: try ThreatFox (free, no key for recent)
    print("[*] Trying ThreatFox fallback (abuse.ch successor, free)...")
    try:
        r = requests.get("https://threatfox.abuse.ch/export/json/recent/", headers=headers, timeout=30)
        if r.status_code == 200:
            # ThreatFox export is JSON lines
            data = r.json()
            RAW_DIR.mkdir(parents=True, exist_ok=True)
            (RAW_DIR / "threatfox_raw.json").write_text(r.text)
            print(f"[+] Saved ThreatFox raw to harddisk {RAW_DIR}/threatfox_raw.json")
            # Normalize ThreatFox format to MalwareBazaar-like
            entries = []
            if isinstance(data, dict):
                # ThreatFox bulk has different structure
                for k, v in data.items():
                    if isinstance(v, dict) and "ioc" in v:
                        entries.append({
                            "sha256_hash": v.get("sha256_hash", ""),
                            "md5_hash": v.get("md5_hash", ""),
                            "sha1_hash": v.get("sha1_hash", ""),
                            "file_name": v.get("threat_type", ""),
                            "signature": v.get("malware", ""),
                            "tags": v.get("tags", []),
                            "first_seen": v.get("first_seen", ""),
                        })
            if entries:
                return entries[:limit]
    except Exception as e:
        print(f"[!] ThreatFox fallback failed: {e}")

    print("[!] No API key found. Set MB_API_KEY env var (get free at https://bazaar.abuse.ch/api/)")
    print("[*] Creating 3 demo hashes for testing scan (offline demo mode)")
    # Demo hashes - not real malware, just to test pipeline
    demo = [
        {"sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "file_name": "empty", "signature": "DemoEmpty", "tags": ["demo"], "first_seen": "2026-10-28"},
        {"sha256_hash": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "file_name": "a", "signature": "DemoA", "tags": ["demo"], "first_seen": "2026-10-28"},
        {"sha256_hash": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d", "file_name": "b", "signature": "DemoB", "tags": ["demo"], "first_seen": "2026-10-28"},
    ]
    return demo[:limit]

def save_to_harddisk(entries: list, json_path: Path = DEFAULT_DB_JSON, sqlite_path: Path = DEFAULT_DB_SQLITE, source: str = "malwarebazaar"):
    """Save entries to both JSON and SQLite harddisk DBs"""
    from .db import add_hash_json, add_hash_sqlite
    import json as js
    added = 0
    for e in entries:
        sha256 = (e.get("sha256_hash") or e.get("sha256") or "").lower()
        if not sha256 or len(sha256) != 64:
            continue
        info = {
            "md5": e.get("md5_hash", e.get("md5", "")),
            "sha1": e.get("sha1_hash", e.get("sha1", "")),
            "file_name": e.get("file_name", ""),
            "signature": e.get("signature", e.get("malware", "")),
            "tags": e.get("tags", []),
            "first_seen": e.get("first_seen", ""),
            "source": source,
        }
        if add_hash_json(sha256, info, json_path):
            added += 1
        entry = {"sha256": sha256, **info}
        add_hash_sqlite(entry, sqlite_path)

    total_json = len(js.loads(Path(json_path).read_text())["hashes"]) if Path(json_path).exists() else 0
    print(f"[+] Added {added} new hashes (total in harddisk JSON: {total_json})")
    return added
