#!/usr/bin/env python3
"""
BadBotIOCScanner - CLI
  python scanner.py update --source malwarebazaar --limit 10
  python scanner.py scan /tmp --db db/hashes.json
  python scanner.py db info
"""
import argparse
import json
import sys
from pathlib import Path

def cmd_update(args):
    from badbot_ioc.fetch import fetch_malwarebazaar, save_to_harddisk
    print(f"[*] Fetching from {args.source} limit={args.limit} tag={args.tag}")
    if args.source == "malwarebazaar":
        entries = fetch_malwarebazaar(limit=args.limit, tag=args.tag)
        if not entries:
            print("[!] No entries fetched (check network/API)")
            return 1
        print(f"[+] Fetched {len(entries)} entries")
        # Save to harddisk (request once)
        save_to_harddisk(entries, json_path=args.db_json, sqlite_path=args.db_sqlite)
        print(f"[+] Harddisk DB: {args.db_json} and {args.db_sqlite}")
        # Show sample
        for e in entries[:3]:
            print(f"  - {e.get('sha256_hash')} {e.get('file_name')} {e.get('signature')}")
    else:
        print(f"[!] Unknown source {args.source}")
        return 1
    return 0

def cmd_scan(args):
    from badbot_ioc.scanner import scan_path
    db = args.db
    # Auto-pick db file
    if not Path(db).exists():
        # Try alternatives
        for alt in ["db/hashes.db", "db/hashes.json"]:
            if Path(alt).exists():
                db = alt
                print(f"[*] DB {args.db} not found, using {alt}")
                break
    print(f"[*] Scanning {args.path} with algo={args.hash} db={db} quick={args.quick}")
    # Check if DB exists, if not warn
    if not Path(db).exists():
        print(f"[!] DB not found: {db} - run `python scanner.py update` first")
        print(f"    Creating empty demo entry for test...")
        # Create demo hit: hash of this file
        from badbot_ioc.hasher import hash_file
        from badbot_ioc.db import add_hash_json
        h = hash_file(__file__, algo=args.hash)
        add_hash_json(h, {"file_name": "demo", "signature": "demo-hit", "source": "local"}, db)
        print(f"    Added demo hash {h} to {db} - re-run scan to see hit")

    # Run scan
    res = scan_path(args.path, db_path=db, algo=args.hash, quick=args.quick)
    print(f"\n=== Scan Complete ===")
    print(f"Scanned: {res['scanned']} files (errors: {res['errors']})")
    print(f"DB: {res['db']} algo={res['algo']}")
    print(f"Hits: {len(res['hits'])}")
    for hit in res["hits"]:
        info = hit["info"]
        sig = info.get("signature") if isinstance(info, dict) else info
        print(f"[DETECTED] {hit['path']} | {hit['sha256'][:16]}... | {sig}")

    if args.output:
        Path(args.output).write_text(json.dumps(res, indent=2))
        print(f"[+] Report saved to {args.output}")

    return 0 if len(res["hits"]) == 0 else 2

def cmd_db(args):
    from badbot_ioc.db import load_json, count_sqlite
    from pathlib import Path as P
    if args.db_action == "info":
        for p in [P("db/hashes.json"), P("db/hashes.db"), P(args.db) if args.db else P("")]:
            if p and p.exists():
                if p.suffix == ".json":
                    d = load_json(p)
                    print(f"[+] {p}: {len(d['hashes'])} hashes (JSON)")
                elif p.suffix == ".db":
                    print(f"[+] {p}: {count_sqlite(p)} hashes (SQLite)")
        if P("db/mb_raw.json").exists():
            print(f"[+] db/mb_raw.json: {P('db/mb_raw.json').stat().st_size} bytes raw cache")
    elif args.db_action == "search":
        from badbot_ioc.db import is_known_json, is_known_sqlite
        h = args.hash
        for p in [P("db/hashes.json"), P("db/hashes.db")]:
            if p.exists():
                info = is_known_json(h, p) if p.suffix==".json" else is_known_sqlite(h, p)
                if info:
                    print(f"[+] Found in {p}: {json.dumps(info, indent=2)}")
                    return 0
        print(f"[-] Not found: {h}")
    return 0

def main():
    p = argparse.ArgumentParser(prog="BadBotIOCScanner", description="Python malware hash scanner - harddisk DB, offline scan")
    sub = p.add_subparsers(dest="cmd", required=True)

    # update
    pu = sub.add_parser("update", help="Fetch from API -> save to harddisk DB")
    pu.add_argument("--source", default="malwarebazaar", choices=["malwarebazaar"], help="API source")
    pu.add_argument("--limit", type=int, default=10, help="Number of hashes to fetch")
    pu.add_argument("--tag", default=None, help="Filter tag e.g. exe, elf")
    pu.add_argument("--db-json", default="db/hashes.json", help="JSON DB path")
    pu.add_argument("--db-sqlite", default="db/hashes.db", help="SQLite DB path")
    pu.set_defaults(func=cmd_update)

    # scan
    ps = sub.add_parser("scan", help="Scan filesystem against harddisk DB (offline)")
    ps.add_argument("path", nargs="?", default=".", help="Path to scan")
    ps.add_argument("--db", default="db/hashes.json", help="DB path (json or db)")
    ps.add_argument("--hash", default="sha256", choices=["sha256","md5","sha1"], help="Hash algo")
    ps.add_argument("--quick", action="store_true", help="Skip /home etc.")
    ps.add_argument("--output", default=None, help="Save JSON report")
    ps.set_defaults(func=cmd_scan)

    # db
    pd = sub.add_parser("db", help="DB utils")
    pd.add_argument("db_action", choices=["info","search"], help="info or search")
    pd.add_argument("--db", default="db/hashes.json", help="DB path")
    pd.add_argument("--hash", default="", help="Hash to search")
    pd.set_defaults(func=cmd_db)

    args = p.parse_args()
    sys.exit(args.func(args))

if __name__ == "__main__":
    main()
