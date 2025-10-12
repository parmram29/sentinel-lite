from __future__ import annotations
import json, os, time
from typing import Any, Dict

class JsonlStore:
    def __init__(self, path: str, rotate_bytes: int = 1_048_576):
        self.path = path
        self.rotate_bytes = rotate_bytes
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def _maybe_rotate(self):
        if os.path.exists(self.path) and os.path.getsize(self.path) >= self.rotate_bytes:
            ts = time.strftime("%Y%m%d-%H%M%S")
            base, ext = os.path.splitext(self.path)
            os.replace(self.path, f"{base}.{ts}{ext}")

    def write(self, record: Dict[str, Any]):
        self._maybe_rotate()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
