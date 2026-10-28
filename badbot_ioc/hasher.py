import hashlib
from pathlib import Path

def hash_file(path: str | Path, algo: str = "sha256", chunk_size: int = 8192) -> str | None:
    """Stream hash file without loading fully into RAM. Returns hex or None on error."""
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    return hashlib.new(algo, data).hexdigest()
