# Technical Spike Plan — Jack Nelson (Team 09, SAL-4)

Written and committed before any test ran.

## Risk being tested

D6 risk 6 and the open D4 question "Normalization tool: Fluent Bit (in the BOM), Logstash, or a custom
script, and whether it meets 5 seconds." Component: Normalization Pipeline and Event Store (owner: Jack Nelson).

## Question (yes/no)

Can Fluent Bit (the tool already in our BOM) convert real Suricata EVE and Zeek JSON output into the
FR-02 schema and index it in OpenSearch so that a new alert is searchable by source IP within 5 seconds
in at least 19 of 20 trials?

## Pass mark (all must hold)

1. **FR-02 completeness:** from a mixed batch of at least 500 Suricata + Zeek events, 100% of records
   stored in the `events` index contain all seven required fields: timestamp, src_ip, dest_ip, ports
   (src_port and dest_port), protocol, sensor, severity. Records that cannot be normalized go to
   `events-rejected`, and stored + rejected must equal input (no silent loss).
2. **FR-03 / NFR-01 latency:** in 20 trials, a new Suricata alert line appended to `eve.json` is returned
   by an OpenSearch query on its unique source IP within 5.0 s of the append, in at least 19 of 20 trials.
3. **Risk 6 record:** OpenSearch heap and container memory are recorded during the run (no pass/fail;
   used to size the EnGeo host).

## Setup (smallest that answers it)

- Public PCAP replayed offline through Suricata (ET Open rules) and Zeek to produce real `eve.json`,
  `conn.log` and `notice.log`.
- OpenSearch 2.17 single node (Docker, 1 GB heap) and Fluent Bit 3.2 (Docker) tailing the log files,
  with a Lua filter that maps both formats to the FR-02 schema and routes failures to `events-rejected`.
- A Python harness that appends a fresh alert, polls OpenSearch every 100 ms, and records the time.
- Runs on a cloud Linux VM (2 vCPU, 8 GB), not the EnGeo host. Time box: one afternoon.

## Not tested

The 15 s dashboard path (FR-13), live capture from a mirrored bridge (Austin's spike), sustained load.
