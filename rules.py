from __future__ import annotations
import os, re
from typing import Dict, Any, Iterable, List

def is_temp_path(path: str, suspicious_paths: Iterable[str]) -> bool:
    p = (path or "").lower()
    return any(sp.lower() in p for sp in suspicious_paths)

def parse_host_port(addr: str | None):
    if not addr or ":" not in addr: 
        return None, None
    host, port = addr.rsplit(":", 1)
    try:
        return host, int(port)
    except ValueError:
        return host, None

def apply_rules(event: Dict[str, Any], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    r = []
    toggles = cfg.get("rules", {})
    suspicious_names = {n.lower() for n in cfg.get("suspicious_names", [])}
    suspicious_paths = cfg.get("suspicious_paths", [])
    safe_ports = set(cfg.get("safe_ports", []))

    if event.get("type") == "process_start":
        name = (event.get("name") or "").lower()
        exe = (event.get("exe") or "")
        if toggles.get("suspicious_process_name") and name in suspicious_names:
            r.append({"rule_id": "suspicious_process_name", "severity": "high",
                      "message": f"Process with suspicious name started: {event.get('name')} (pid {event.get('pid')})"})
        if toggles.get("execution_from_temp") and is_temp_path(exe, suspicious_paths):
            r.append({"rule_id": "execution_from_temp", "severity": "medium",
                      "message": f"Process executing from temp-like path: {exe} (pid {event.get('pid')})"})

    if event.get("type") == "net_outbound":
        host, port = parse_host_port(event.get("raddr"))
        if port and (port not in safe_ports) and port >= 1024:
            r.append({"rule_id": "rare_outbound_port", "severity": "low",
                      "message": f"New outbound connection to uncommon port {port} by {event.get('process')} (pid {event.get('pid')})"})

    if event.get("type") == "persistence_new":
        if toggles.get("new_persistence_entry"):
            loc = event.get("loc")
            path = event.get("path")
            r.append({"rule_id": "new_persistence_entry", "severity": "medium",
                      "message": f"New persistence entry detected at {loc}: {path}"})

    return r
