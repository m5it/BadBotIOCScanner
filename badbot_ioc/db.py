import json
import sqlite3
from pathlib import Path
from typing import Optional

DEFAULT_JSON = Path("db/hashes.json")
DEFAULT_DB = Path("db/hashes.db")

# JSON helpers
def load_json(path: str | Path = DEFAULT_JSON) -> dict:
    p = Path(path)
    if not p.exists():
        return {"hashes": {}, "meta": {"count": 0}}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"hashes": {}, "meta": {"count": 0}}

def save_json(data: dict, path: str | Path = DEFAULT_JSON):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))

def add_hash_json(sha256: str, info: dict, path: str | Path = DEFAULT_JSON):
    db = load_json(path)
    if sha256 not in db["hashes"]:
        db["hashes"][sha256] = info
        db["meta"]["count"] = len(db["hashes"])
        save_json(db, path)
        return True
    return False

def is_known_json(sha256: str, path: str | Path = DEFAULT_JSON) -> Optional[dict]:
    db = load_json(path)
    return db["hashes"].get(sha256.lower())

def json_to_set(path: str | Path = DEFAULT_JSON) -> set:
    db = load_json(path)
    return set(k.lower() for k in db["hashes"].keys())

# SQLite helpers
def init_sqlite(path: str | Path = DEFAULT_DB):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p)
    con.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            sha256 TEXT PRIMARY KEY,
            md5 TEXT,
            sha1 TEXT,
            file_name TEXT,
            signature TEXT,
            tags TEXT,
            first_seen TEXT,
            source TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON hashes(sha256)")
    con.commit()
    con.close()

def add_hash_sqlite(entry: dict, path: str | Path = DEFAULT_DB):
    init_sqlite(path)
    con = sqlite3.connect(path)
    try:
        con.execute("""
            INSERT OR IGNORE INTO hashes (sha256, md5, sha1, file_name, signature, tags, first_seen, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.get("sha256", "").lower(),
            entry.get("md5", ""),
            entry.get("sha1", ""),
            entry.get("file_name", ""),
            entry.get("signature", ""),
            ",".join(entry.get("tags", [])) if isinstance(entry.get("tags"), list) else entry.get("tags", ""),
            entry.get("first_seen", ""),
            entry.get("source", "malwarebazaar"),
        ))
        con.commit()
    finally:
        con.close()

def is_known_sqlite(sha256: str, path: str | Path = DEFAULT_DB) -> Optional[dict]:
    p = Path(path)
    if not p.exists():
        return None
    con = sqlite3.connect(p)
    con.row_factory = sqlite3.Row
    cur = con.execute("SELECT * FROM hashes WHERE sha256=?", (sha256.lower(),))
    row = cur.fetchone()
    con.close()
    if row:
        return dict(row)
    return None

def count_sqlite(path: str | Path = DEFAULT_DB) -> int:
    p = Path(path)
    if not p.exists():
        return 0
    con = sqlite3.connect(p)
    cur = con.execute("SELECT COUNT(*) FROM hashes")
    n = cur.fetchone()[0]
    con.close()
    return n

def sync_json_to_sqlite(json_path: str | Path = DEFAULT_JSON, db_path: str | Path = DEFAULT_DB):
    """Convert JSON harddisk DB to SQLite for fast scanning"""
    db = load_json(json_path)
    for sha256, info in db["hashes"].items():
        entry = {"sha256": sha256, **info}
        add_hash_sqlite(entry, db_path)
