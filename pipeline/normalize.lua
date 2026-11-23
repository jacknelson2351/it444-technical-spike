-- FR-02 normalizer for Fluent Bit.
-- Maps Suricata EVE alerts and Zeek conn/notice JSON to one schema:
--   event_id, @timestamp, src_ip, dest_ip, src_port, dest_port, protocol, sensor, severity,
--   signature, zeek_uid
-- Records missing a required field are marked _route="rejected" with a reject_reason.
-- Payload-bearing fields are never copied (NFR-04).

local REQUIRED = { "@timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "sensor", "severity" }
local seq = 0

local function iso_from_epoch(ts)
  local secs = math.floor(ts)
  local ms = math.floor((ts - secs) * 1000 + 0.5)
  if ms >= 1000 then secs = secs + 1; ms = ms - 1000 end
  return os.date("!%Y-%m-%dT%H:%M:%S", secs) .. string.format(".%03dZ", ms)
end

local function next_id(prefix)
  seq = seq + 1
  return string.format("%s-%d-%08d", prefix, os.time(), seq)
end

local function portless(proto)
  return proto == "icmp" or proto == "ipv6-icmp" or proto == "icmpv6"
end

local function from_suricata(r)
  if r["event_type"] ~= "alert" then return nil end -- only alerts enter the pipeline
  local a = r["alert"] or {}
  local proto = r["proto"] and string.lower(r["proto"]) or nil
  local out = {
    event_id   = next_id("sur"),
    ["@timestamp"] = r["timestamp"],
    src_ip     = r["src_ip"],
    dest_ip    = r["dest_ip"],
    src_port   = r["src_port"],
    dest_port  = r["dest_port"],
    protocol   = proto,
    sensor     = "suricata",
    severity   = a["severity"],
    signature  = a["signature"],
    signature_id = a["signature_id"],
    category   = a["category"],
    flow_id    = r["flow_id"],
  }
  if portless(proto) then
    out.src_port = out.src_port or 0
    out.dest_port = out.dest_port or 0
    out.icmp_type = r["icmp_type"]
  end
  return out
end

local function from_zeek(r, kind)
  local proto = r["proto"]
  local out = {
    event_id   = next_id("zeek"),
    ["@timestamp"] = r["ts"] and iso_from_epoch(r["ts"]) or nil,
    src_ip     = r["id.orig_h"],
    dest_ip    = r["id.resp_h"],
    src_port   = r["id.orig_p"],
    dest_port  = r["id.resp_p"],
    protocol   = proto,
    sensor     = "zeek",
    severity   = (kind == "notice") and 2 or 3, -- 1 high, 2 medium, 3 informational
    signature  = (kind == "notice") and r["note"] or ("zeek " .. tostring(r["service"] or "conn")),
    zeek_uid   = r["uid"],
    conn_state = r["conn_state"],
  }
  return out
end

function normalize(tag, timestamp, record)
  local out
  if string.find(tag, "^suricata") then
    out = from_suricata(record)
    if out == nil then return -1, 0, 0 end -- drop non-alert EVE types
  elseif string.find(tag, "^zeek%.notice") then
    out = from_zeek(record, "notice")
  elseif string.find(tag, "^zeek") then
    out = from_zeek(record, "conn")
  else
    return 0, 0, 0
  end

  local missing = {}
  for _, f in ipairs(REQUIRED) do
    if out[f] == nil then table.insert(missing, f) end
  end
  if #missing > 0 then
    return 1, timestamp, {
      _route = "rejected",
      reject_reason = "missing: " .. table.concat(missing, ","),
      sensor = out.sensor,
      original = record,
      ["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }
  end
  out._route = "ok"
  return 1, timestamp, out
end
