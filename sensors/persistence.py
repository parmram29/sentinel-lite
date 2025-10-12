from __future__ import annotations
import os, time, sys
from typing import List, Dict, Any

def expand_dirs(paths: List[str]) -> List[str]:
    return [os.path.abspath(os.path.expanduser(p)) for p in paths]

def list_dir_entries(d: str) -> List[Dict[str, Any]]:
    out = []
    try:
        for name in os.listdir(d):
            path = os.path.join(d, name)
            try:
                st = os.stat(path)
                out.append({"path": path, "mtime": st.st_mtime, "ctime": st.st_ctime, "is_dir": os.path.isdir(path)})
            except FileNotFoundError:
                continue
    except Exception:
        pass
    return out

def snapshot_persistence(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if sys.platform == "darwin":
        for d in expand_dirs(cfg.get("persistence", {}).get("macos_dirs", [])):
            entries += [{"type": "persistence_entry", "loc": d, **e, "ts": time.time()} for e in list_dir_entries(d)]
    elif sys.platform.startswith("linux"):
        for d in expand_dirs(cfg.get("persistence", {}).get("linux_dirs", [])):
            entries += [{"type": "persistence_entry", "loc": d, **e, "ts": time.time()} for e in list_dir_entries(d)]
    elif os.name == "nt":
        # Windows: read Run keys
        try:
            import winreg
            run_keys = cfg.get("persistence", {}).get("windows_run_keys", [])
            reg_roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
            for key_path in run_keys:
                root_name, subkey = key_path.split("\\", 1)
                root = reg_roots.get(root_name)
                if not root: 
                    continue
                try:
                    with winreg.OpenKey(root, subkey) as h:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(h, i)
                                entries.append({"type": "persistence_entry", "loc": key_path, "path": str(value), "name": name, "ts": time.time(), "is_dir": False})
                                i += 1
                            except OSError:
                                break
                except OSError:
                    continue
        except Exception:
            pass
    return entries

def diff_new_entries(prev: List[Dict[str, Any]], curr: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    prev_set = {(e.get("loc"), e.get("path"), e.get("name")) for e in prev}
    events = []
    for e in curr:
        key = (e.get("loc"), e.get("path"), e.get("name"))
        if key not in prev_set:
            events.append(e | {"type": "persistence_new"})
    return events
