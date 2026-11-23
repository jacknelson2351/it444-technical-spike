#!/usr/bin/env bash
# Step 1: turn the PCAPs into real sensor output (Suricata EVE + Zeek JSON).
# PCAPs: chrissanders/packets (Practical Packet Analysis captures) + Austin's nmap_syn_n.pcap from the team repo.
set -euo pipefail
IN=${1:-pcaps}; OUT=${2:-sensor_logs}
for f in "$IN"/*; do
  n=$(basename "$f"); n=${n%.*}; mkdir -p "$OUT/$n"
  if [ "$n" = "nmap_syn_n" ]; then RULES="-S pipeline/local.rules"; else RULES=""; fi   # as run: ET Open for all, custom SYN rule alone for the scan capture
  suricata -r "$f" -l "$OUT/$n" -k none $RULES >/dev/null
  docker run --rm -v "$PWD/$IN":/in:ro -v "$PWD/$OUT/$n":/out -w /out zeek/zeek:7.0 \
    zeek -C -r "/in/$(basename "$f")" LogAscii::use_json=T >/dev/null
done
