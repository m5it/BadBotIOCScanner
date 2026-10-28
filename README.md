# BadBotIOCScanner

Python malware hash scanner - sister project to **BadBotSearch** (Go).

- **BadBotSearch (Go)** = Linux supply-chain scanner (Spybot-like, `xz` backdoor, `dpkg -V`, persistence)
- **BadBotIOCScanner (Python)** = File hash scanner (SHA256/MD5/SHA1, MalwareBazaar, local harddisk DB)

## Features

- `scan` - Walk filesystem, hash files, check against local DB (offline, no upload)
- `update` - Fetch from APIs (MalwareBazaar abuse.ch) -> save to harddisk `db/` (request once, inform from disk second time)
- `db` - SQLite + JSON harddisk DB, dedup, allowlist

## Quick Start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Update DB from API (saves to harddisk)
python scanner.py update --source malwarebazaar --limit 100
python scanner.py update --source malwarebazaar --tag exe --limit 50

# Scan (offline from harddisk)
python scanner.py scan /tmp --db db/hashes.json
python scanner.py scan /home --quick --db db/hashes.db
python scanner.py scan /usr/bin --hash sha256 --db db/hashes.db

# DB info
python scanner.py db info
python scanner.py db search --hash <sha256>
```

## Harddisk DB

- `db/hashes.json` - JSON list (portable, git-friendly, small)
- `db/hashes.db` - SQLite (fast for >100k hashes, indexed)

Second run reads only from disk - no API call. `update` uses ETag/conditional fetch where possible.

## APIs Supported

- **MalwareBazaar (abuse.ch)** - `https://mb-api.abuse.ch/api/v1/` - free, no key, POST `query=get_recent` etc.
- More: VirusTotal (optional key), MalShare placeholder

## Project Structure

```
BadBotIOCScanner/
├── scanner.py          # CLI entry (scan/update/db)
├── badbot_ioc/
│   ├── __init__.py
│   ├── hasher.py       # SHA256/MD5/SHA1 streaming
│   ├── scanner.py      # Walk + match
│   ├── db.py           # JSON/SQLite harddisk DB
│   └── fetch.py        # MalwareBazaar API -> harddisk
├── db/                 # harddisk DB (gitignored, create via update)
│   ├── hashes.json
│   └── hashes.db
├── tests/
└── requirements.txt
```
