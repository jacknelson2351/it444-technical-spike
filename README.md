# IT 444 Technical Spike — Jack Nelson (Team 09)

**Question:** Can Fluent Bit normalize real Suricata EVE and Zeek JSON to the FR-02 schema and index it in
OpenSearch so a new alert is searchable by source IP within 5 s in at least 19 of 20 trials?
The plan and pass mark are in `SPIKE_PLAN.md` (first commit, before any test ran).

**Result: PASS.** 1,143 of 1,143 stored events have every FR-02 field; 2 of 2 malformed records went to
`events-rejected`; 20 of 20 latency trials under 5 s (median 0.99 s, max 1.20 s), and 20 of 20 again
with ~1,000 events/s of background load (median 1.08 s, max 1.41 s). See `results/`.

| Path | What it is |
|---|---|
| `SPIKE_PLAN.md` | Question, pass mark, setup (committed first) |
| `pipeline/fluent-bit.conf`, `pipeline/normalize.lua` | The normalization pipeline under test |
| `pipeline/local.rules` | Austin's custom SYN-scan rule (ET Open does not flag the scan) |
| `run_sensors.sh` | PCAP → Suricata `eve.json` + Zeek `conn.log` |
| `sensor_logs/` | The real sensor output that was ingested |
| `latency_trials.py`, `load_gen.py` | Timing harness and background load generator |
| `results/` | Raw outputs: completeness check, reject test, latency JSON + logs, versions |

## Reproduce
```
# OpenSearch 2.17.1 single node, security plugin off, 1 GB heap, on 127.0.0.1:9200
bash run_sensors.sh pcaps sensor_logs
mkdir -p run/data/suricata run/data/zeek run/state
cat sensor_logs/*/eve.json > run/data/suricata/eve.json; cat sensor_logs/*/conn.log > run/data/zeek/conn.log; touch run/data/zeek/notice.log
docker run -d --name fb --network host -v $PWD/pipeline:/pipeline:ro \
  -v $PWD/pipeline/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro \
  -v $PWD/run/data:/data -v $PWD/run/state:/state fluent/fluent-bit:3.2
python3 latency_trials.py run/data/suricata/eve.json results/latency_results.json
```
