from __future__ import annotations
import time, os, yaml
from typing import Dict, Any, List

from store import JsonlStore
from alerting import Alerter
from sensors.processes import snapshot_processes, diff_processes
from sensors.network import snapshot_connections, new_outbounds
from sensors.persistence import snapshot_persistence, diff_new_entries
from rules import apply_rules

def load_config() -> Dict[str, Any]:
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main():
    cfg = load_config()
    os.makedirs("logs", exist_ok=True)
    event_store = JsonlStore("logs/events.jsonl", rotate_bytes=cfg.get("log_rotation_bytes", 1_048_576))
    alerter = Alerter("logs/alerts.jsonl", rotate_bytes=cfg.get("log_rotation_bytes", 1_048_576))

    # Baselines
    prev_procs = snapshot_processes()
    prev_conns = snapshot_connections()
    prev_persist = snapshot_persistence(cfg)

    t_last = {"proc": 0.0, "net": 0.0, "persist": 0.0}
    ints = cfg.get("intervals", {})
    iproc = float(ints.get("processes", 5))
    inet = float(ints.get("network", 10))
    ipers = float(ints.get("persistence", 30))

    print("sentinel-lite running. Ctrl+C to stop.")
    try:
        while True:
            now = time.time()

            # Processes
            if now - t_last["proc"] >= iproc:
                curr = snapshot_processes()
                events = diff_processes(prev_procs, curr)
                for e in events:
                    event_store.write(e)
                    for alert in apply_rules(e, cfg):
                        alerter.alert(alert["rule_id"], alert["severity"], alert["message"], e)
                prev_procs = curr
                t_last["proc"] = now

            # Network
            if now - t_last["net"] >= inet:
                curr = snapshot_connections()
                events = new_outbounds(prev_conns, curr)
                for e in events:
                    event_store.write(e)
                    for alert in apply_rules(e, cfg):
                        alerter.alert(alert["rule_id"], alert["severity"], alert["message"], e)
                prev_conns = curr
                t_last["net"] = now

            # Persistence
            if now - t_last["persist"] >= ipers:
                curr = snapshot_persistence(cfg)
                events = diff_new_entries(prev_persist, curr)
                for e in events:
                    event_store.write(e)
                    for alert in apply_rules(e, cfg):
                        alerter.alert(alert["rule_id"], alert["severity"], alert["message"], e)
                prev_persist = curr
                t_last["persist"] = now

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping sentinel-lite.")

if __name__ == "__main__":
    main()
