import os
from pathlib import Path
from typing import Optional
from .hasher import hash_file
from .db import is_known_json, is_known_sqlite, count_sqlite, load_json

SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/snap"}
# /tmp is skipped only when scanning from / (not when user explicitly scans /tmp)
SKIP_DIRS_ROOT_ONLY = {"/proc", "/sys", "/dev", "/run", "/snap", "/tmp"}

def scan_path(root: str | Path, db_path: str | Path = "db/hashes.json", algo: str = "sha256", quick: bool = False, use_sqlite: bool = True) -> dict:
    """
    Scan filesystem, hash files, check against harddisk DB (offline).
    Returns {"scanned": int, "hits": list, "errors": int}
    """
    root = Path(root)
    db_path = Path(db_path)
    # Auto-detect DB type
    if use_sqlite and str(db_path).endswith(".db"):
        check_fn = lambda h: is_known_sqlite(h, db_path)
    elif db_path.suffix == ".db":
        check_fn = lambda h: is_known_sqlite(h, db_path)
    else:
        # JSON fallback
        check_fn = lambda h: is_known_json(h, db_path)
        # For speed, load set once
        from .db import json_to_set
        known_set = json_to_set(db_path)
        check_fn = lambda h: {"hit": True} if h in known_set else None
        # But we want info, so keep is_known_json for details
        check_fn = lambda h: is_known_json(h, db_path)

    scanned = 0
    hits = []
    errors = 0

    # If root is a single file, hash it directly (don't skip)
    if root.is_file():
        h = hash_file(root, algo=algo)
        if h:
            info = check_fn(h)
            if info:
                hits.append({"path": str(root), "sha256": h, "info": info})
            scanned = 1
        return {"scanned": scanned, "hits": hits, "errors": errors, "db": str(db_path), "algo": algo}

    # Choose skip set: only skip /tmp when scanning from /
    skip_set = SKIP_DIRS_ROOT_ONLY if str(root) == "/" else SKIP_DIRS

    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None, followlinks=False):
        # Skip system dirs
        if dirpath in skip_set or any(dirpath.startswith(s + "/") for s in skip_set):
            dirnames[:] = []
            continue
        if quick and dirpath in ("/home", "/var/tmp", "/var/cache"):
            dirnames[:] = []
            continue
        # Don't descend into skip dirs
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in skip_set]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            # Skip large files >100MB to keep fast
            try:
                if os.path.getsize(fpath) > 100 * 1024 * 1024:
                    continue
            except:
                continue

            scanned += 1
            h = hash_file(fpath, algo=algo)
            if h is None:
                errors += 1
                continue
            info = check_fn(h)
            if info:
                hits.append({
                    "path": fpath,
                    "sha256": h,
                    "info": info,
                })

            # Simple progress
            if scanned % 5000 == 0:
                print(f"  ... scanned {scanned}, hits {len(hits)}")

    return {"scanned": scanned, "hits": hits, "errors": errors, "db": str(db_path), "algo": algo}
