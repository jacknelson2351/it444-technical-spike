const fs = require("fs");
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, ShadingType,
  LevelFormat, AlignmentType, BorderStyle } = require("docx");

const REPO = process.env.REPO || "[PASTE YOUR GITHUB REPO URL]";
const F = "Calibri";
const P = (text, o = {}) => new Paragraph({ spacing: { after: 70 }, ...o,
  children: (Array.isArray(text) ? text : [text]).map(t => typeof t === "string" ? new TextRun({ text: t, font: F, size: 21 }) : t) });
const B = (t) => new TextRun({ text: t, font: F, size: 21, bold: true });
const T = (t) => new TextRun({ text: t, font: F, size: 21 });
const H = (t) => new Paragraph({ spacing: { before: 110, after: 50 }, keepNext: true,
  children: [new TextRun({ text: t, font: F, size: 23, bold: true, color: "1F3864" })] });
const bullet = (runs) => new Paragraph({ numbering: { reference: "b", level: 0 }, spacing: { after: 35 },
  children: (Array.isArray(runs) ? runs : [runs]).map(t => typeof t === "string" ? T(t) : t) });

const cols = [2700, 2350, 2350, 1200, 1040];
const W = cols.reduce((a, b) => a + b, 0);
const border = { style: BorderStyle.SINGLE, size: 4, color: "999999" };
const cell = (t, i, head, fill) => new TableCell({
  width: { size: cols[i], type: WidthType.DXA },
  borders: { top: border, bottom: border, left: border, right: border },
  shading: head ? { type: ShadingType.CLEAR, fill: "D9E2F3" } : fill ? { type: ShadingType.CLEAR, fill } : undefined,
  margins: { top: 30, bottom: 30, left: 70, right: 70 },
  children: [new Paragraph({ children: [new TextRun({ text: t, font: F, size: 19, bold: head })] })] });
const row = (cells, head, fill) => new TableRow({ children: cells.map((c, i) => cell(c, i, head, i === 4 && !head ? fill : undefined)) });

const table = new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: cols, rows: [
  row(["Check", "Pass mark", "Measured", "Median / max", "Result"], true),
  row(["FR-02 completeness (1,143 real events: 81 Suricata alerts, 1,062 Zeek conn)", "100% of stored records have all 7 fields; stored + rejected = input", "1,143 / 1,143 complete; 0 lost; 2 / 2 malformed test records sent to events-rejected", "–", "PASS"], false, "E2EFDA"),
  row(["FR-03 / NFR-01 latency, idle", "≤ 5.0 s in ≥ 19 / 20", "20 / 20 under 5 s", "0.99 s / 1.20 s", "PASS"], false, "E2EFDA"),
  row(["Same, with ~1,000 events/s background load (supplementary)", "≤ 5.0 s in ≥ 19 / 20", "20 / 20 under 5 s; 119,800 load events, all indexed", "1.08 s / 1.41 s", "PASS"], false, "E2EFDA"),
  row(["Risk 6: OpenSearch memory (record only)", "No pass mark", "Heap 127 → 615 MB of 1,024 MB at ~121k docs; process RSS 1,364 → 1,401 MB", "–", "Recorded"], false, "F2F2F2"),
] });

const doc = new Document({
  numbering: { config: [{ reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
    style: { paragraph: { indent: { left: 300, hanging: 200 } } } }] }] },
  sections: [{ properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1000, bottom: 1000, left: 1080, right: 1080 } } },
  children: [
    new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: "IT 444 Individual Technical Spike Report", font: F, size: 30, bold: true })] }),
    P("Jack Nelson | Team 09 (AI security assistant for home networks) | Risk from D4 / D6 risk 6: normalization and indexing latency | Run on 23 Nov 2026"),

    H("1. Question and pass mark (written and committed before any test ran)"),
    P([B("Requirement: "), T("FR-02 (single normalized schema), FR-03 and NFR-01 (indexed within 5 s). It also answers the open D4 question \"Fluent Bit, Logstash, or a custom script, and does it meet 5 seconds?\" and D6 risk 6 (one host pushing indexing past 5 s).")]),
    P([B("Question: "), T("Can Fluent Bit, the tool already in our BOM, convert real Suricata EVE and Zeek JSON into the FR-02 schema and index it in OpenSearch so that a new alert is searchable by source IP within 5 seconds in at least 19 of 20 trials?")]),
    P([B("Pass mark (all must hold): "), T("(1) at least 500 mixed events, with 100% of stored records containing timestamp, source and destination IP, ports, protocol, sensor and severity, and stored + rejected = input; (2) a new alert line appended to eve.json is returned by a query on its unique source IP within 5.0 s in at least 19 of 20 trials. OpenSearch memory is recorded for risk 6 with no pass mark.")]),

    H("2. Setup (smallest that answers it)"),
    P("Nine captures replayed offline: eight public ones from the Practical Packet Analysis set (exploit kit to CryptoWall 4, Aurora, DVWA SQL injection and directory traversal, DNS zone transfer, ICMP traceroute, ARP poisoning) and Austin's Nmap SYN scan from the team repo. Suricata 7.0.3 with ET Open (53,529 rules) plus Austin's custom SYN-scan rule, and Zeek 7.0.9, produced real eve.json and conn.log. Fluent Bit 3.2 tails the files, and a Lua filter maps both formats to the FR-02 schema, drops non-alert EVE types and payload fields, and re-tags incomplete records to an events-rejected index. OpenSearch 2.17.1 runs as a single node with a 1 GB heap. A Python harness appends a fresh alert, polls OpenSearch every 100 ms, and records the time. Host: Linux cloud VM, 2 vCPU, 6 GB RAM (the EnGeo host was not available). Time box: one afternoon."),

    H("3. Results"),
    table,
    new Paragraph({ spacing: { after: 40 }, children: [] }),
    bullet("The spike passed on every measure. Latency is about 1 s and nearly constant because it is set by Fluent Bit's 1 s flush plus OpenSearch's 1 s refresh, not by load. That leaves about 4 s of margin under FR-03 and about 14 s of the 15 s FR-13 dashboard budget for the sensor and dashboard."),
    bullet("ET Open raised no alert on the Nmap scan; only Austin's custom rule did (50 alerts). This confirms his finding that the custom rule must ship with the sensor."),
    bullet("Two schema gaps showed up. ICMP has no ports, so the pipeline stores 0 and keeps icmp_type. Zeek conn records have no severity, so the pipeline assigns 3 (informational) and notices 2. The team has not agreed on either rule yet. Also, an internal routing field (_route) leaked into the index and must be stripped."),

    H("4. What it means for our design"),
    P([B("Decision: "), T("use Fluent Bit for the Normalization Pipeline, with a Lua mapping and a rewrite_tag route to events-rejected. Logstash and a custom script are not needed, and the open question in System Design is closed. Risk 6 drops from 4 to 2 (likelihood 1), since the bottleneck is fixed flush and refresh intervals, not host size.")]),
    bullet("Add to FR-02: ports are 0 for portless protocols, and each sensor's severity mapping is defined (Suricata 1 to 3 as-is, Zeek notice 2, Zeek conn 3). Michael and Austin should confirm, since the Summarizer and Correlator use severity."),
    bullet("Size OpenSearch at a 4 GB heap on the EnGeo host. Heap reached 60% of 1 GB at only 121k documents, and NFR-05's 7-day retention will hold more."),
    bullet("Tell Ryan the query contract is src_ip.keyword, dest_ip.keyword, sensor.keyword and @timestamp, and that live data is now in OpenSearch for his FR-13 retest. Tell Michael that FR-23 means turning the security plugin back on, which must be re-timed."),
    P([B("IT 445 should first: "), T("strip _route, add an index template that pins field types, and re-run both scripts on the EnGeo host against Austin's live mirrored sensor with the security plugin enabled.")]),

    H("5. Limits of this result"),
    P("Run on a 2-vCPU cloud VM, not the EnGeo host. Logs came from offline PCAP replay, not live capture, and most captures are older public samples. Latency is measured from the log line being written to it being searchable, so it excludes sensor detection time (Austin measured that) and dashboard rendering. One run per condition. Zeek notice.log was configured but empty because no notices fired, so that path is untested. The OpenSearch security plugin was off. The pass mark was kept as set before the run."),

    H("6. Evidence"),
    bullet([T("Repository with commit history (the plan and pass mark are the first commit, before any results): "), B(REPO)]),
    bullet("In the repository: SPIKE_PLAN.md; pipeline/fluent-bit.conf and normalize.lua; run_sensors.sh; sensor_logs/ (the real Suricata and Zeek output that was ingested); latency_trials.py and load_gen.py; results/ (raw latency JSON and logs, the completeness check, the reject test, and tool versions); evidence/1 to 5 (screenshots of each run)."),
  ] }] });

Packer.toBuffer(doc).then(b => fs.writeFileSync(process.argv[2] || "Nelson_Jack_Spike.docx", b));
