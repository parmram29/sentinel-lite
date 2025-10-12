from __future__ import annotations
import time
from typing import Dict, Any
from store import JsonlStore

class Alerter:
    def __init__(self, alert_path: str, rotate_bytes: int):
        self.store = JsonlStore(alert_path, rotate_bytes)

    def alert(self, rule_id: str, severity: str, message: str, context: Dict[str, Any]):
        evt = {
            "ts": time.time(),
            "rule": rule_id,
            "severity": severity,
            "message": message,
            "context": context,
        }
        # Console
        print(f"[ALERT][{severity}][{rule_id}] {message}")
        # File
        self.store.write(evt)
