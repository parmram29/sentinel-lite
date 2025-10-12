from __future__ import annotations
import psutil, time
from typing import List, Dict, Any, Tuple

def snapshot_connections() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in psutil.net_connections(kind="inet"):
        laddr = f"{getattr(c.laddr, 'ip', None)}:{getattr(c.laddr, 'port', None)}" if c.laddr else None
        raddr = f"{getattr(c.raddr, 'ip', None)}:{getattr(c.raddr, 'port', None)}" if c.raddr else None
        try:
            pid = c.pid
            pname = psutil.Process(pid).name() if pid else None
        except Exception:
            pid, pname = None, None
        out.append({
            "type": "net_conn",
            "ts": time.time(),
            "status": c.status,
            "laddr": laddr,
            "raddr": raddr,
            "pid": pid,
            "process": pname,
            "family": str(c.family),
            "type_desc": str(c.type),
        })
    return out

def new_outbounds(prev: List[Dict[str, Any]], curr: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    prev_set = {(e.get("pid"), e.get("raddr")) for e in prev if e.get("raddr")}
    events = []
    for e in curr:
        if e.get("raddr") and (e.get("pid"), e.get("raddr")) not in prev_set and e.get("status") in ("ESTABLISHED", "SYN_SENT"):
            events.append(e | {"type": "net_outbound"})
    return events
