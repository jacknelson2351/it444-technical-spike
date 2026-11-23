"""FR-03 / NFR-01 latency spike.

Appends a fresh Suricata alert (unique source IP) to eve.json, then polls OpenSearch every 100 ms
until a query on that source IP returns it. Pass: <= 5.0 s in at least 19 of 20 trials.
Also records OpenSearch heap and process memory (risk 6).
"""
import json, os, subprocess, sys, time, urllib.request
from datetime import datetime, timezone

EVE = sys.argv[1] if len(sys.argv) > 1 else "/home/claude/run/data/suricata/eve.json"
OS = "http://localhost:9200"
TRIALS, LIMIT, POLL, GAP, TIMEOUT = 20, 5.0, 0.1, 3.0, 30.0


def search(ip):
    body = json.dumps({"query": {"term": {"src_ip.keyword": ip}}}).encode()
    r = urllib.request.Request(f"{OS}/events/_search", data=body, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["hits"]["total"]["value"]


def memory():
    s = json.load(urllib.request.urlopen(f"{OS}/_nodes/stats/jvm,os,process"))
    n = next(iter(s["nodes"].values()))
    pid = subprocess.run(["pgrep", "-f", "org.opensearch.bootstrap.OpenSearch"], capture_output=True, text=True).stdout.split()[0]
    rss_kb = int(open(f"/proc/{pid}/status").read().split("VmRSS:")[1].split()[0])
    return {
        "heap_used_mb": round(n["jvm"]["mem"]["heap_used_in_bytes"] / 2**20),
        "heap_max_mb": round(n["jvm"]["mem"]["heap_max_in_bytes"] / 2**20),
        "process_rss_mb": round(rss_kb / 1024),
        "host_mem_total_mb": round(n["os"]["mem"]["total_in_bytes"] / 2**20),
    }


results = []
mem_before = memory()
for i in range(1, TRIALS + 1):
    ip = f"{os.environ.get("NET","198.51.100")}.{i}"
    line = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "flow_id": 9000000 + i, "event_type": "alert", "src_ip": ip, "src_port": 40000 + i,
        "dest_ip": "192.168.1.50", "dest_port": 22, "proto": "TCP",
        "alert": {"action": "allowed", "signature_id": 9000001, "signature": "SPIKE SYN SCAN",
                  "category": "Attempted Information Leak", "severity": 2},
    }
    with open(EVE, "a") as f:
        f.write(json.dumps(line) + "\n")
        f.flush(); os.fsync(f.fileno())
    t0 = time.monotonic()
    dt = None
    while time.monotonic() - t0 < TIMEOUT:
        if search(ip) > 0:
            dt = time.monotonic() - t0
            break
        time.sleep(POLL)
    ok = dt is not None and dt <= LIMIT
    results.append({"trial": i, "src_ip": ip, "seconds": round(dt, 2) if dt else None, "pass": ok})
    print(f"trial {i:2d}  {ip:<15} {('%.2f s' % dt) if dt else 'TIMEOUT':>8}  {'PASS' if ok else 'FAIL'}", flush=True)
    time.sleep(GAP)

mem_after = memory()
secs = sorted(r["seconds"] for r in results if r["seconds"] is not None)
passed = sum(r["pass"] for r in results)
summary = {
    "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "passed": passed, "trials": TRIALS, "limit_s": LIMIT, "required": 19,
    "result": "PASS" if passed >= 19 else "FAIL",
    "min_s": secs[0], "median_s": secs[len(secs) // 2] if len(secs) % 2 else round((secs[len(secs)//2-1] + secs[len(secs)//2]) / 2, 2),
    "max_s": secs[-1], "mean_s": round(sum(secs) / len(secs), 2),
    "memory_before": mem_before, "memory_after": mem_after, "trials_detail": results,
}
print(json.dumps({k: v for k, v in summary.items() if k != "trials_detail"}, indent=2))
json.dump(summary, open(sys.argv[2] if len(sys.argv) > 2 else "latency_results.json", "w"), indent=2)
