from __future__ import annotations
import psutil, time, os
from typing import Dict, Any, List, Tuple

def snapshot_processes() -> Dict[int, Dict[str, Any]]:
    procs: Dict[int, Dict[str, Any]] = {}
    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cwd", "create_time", "username", "cmdline"]):
        info = p.info
        procs[info["pid"]] = {
            "pid": info.get("pid"),
            "ppid": info.get("ppid"),
            "name": (info.get("name") or "")[:260],
            "exe": (info.get("exe") or "")[:500],
            "cwd": (info.get("cwd") or "")[:500],
            "create_time": info.get("create_time", 0.0),
            "username": info.get("username"),
            "cmdline": info.get("cmdline", [])[:40],
            "ts": time.time(),
        }
    return procs

def diff_processes(prev: Dict[int, Dict[str, Any]], curr: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    new_pids = set(curr.keys()) - set(prev.keys())
    for pid in new_pids:
        events.append({"type": "process_start", **curr[pid]})
    # (Optionally detect exits or image changes)
    return events
