#!/usr/bin/env bash
# Validate UniFi decoders/rules against sample log lines using the Wazuh Server API.
# Requires: WAZUH_API_USER, WAZUH_API_PASS, WAZUH_HOST in the environment.
# Usage: WAZUH_HOST=192.0.2.243 WAZUH_API_USER=... WAZUH_API_PASS=... ./validate.sh
set -euo pipefail
: "${WAZUH_HOST:?set WAZUH_HOST}"; : "${WAZUH_API_USER:?}"; : "${WAZUH_API_PASS:?}"
API="https://${WAZUH_HOST}:55000"

TOK=$(curl -sk -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" \
  "${API}/security/user/authenticate?raw=true")

logtest () {
  local line="$1" desc="$2"
  local out
  out=$(curl -sk -X PUT "${API}/logtest" \
    -H "Authorization: Bearer ${TOK}" -H "Content-Type: application/json" \
    --data "$(python3 -c 'import json,sys;print(json.dumps({"event":sys.argv[1],"log_format":"syslog","location":"192.0.2.1"}))' "$line")")
  echo "--- ${desc}"
  echo "$out" | python3 -c 'import json,sys;d=json.load(sys.stdin).get("data",{});o=d.get("output",{});print("   decoder=%s rule=%s level=%s alert=%s"%(o.get("decoder",{}).get("name"),o.get("rule",{}).get("id"),o.get("rule",{}).get("level"),d.get("alert")))'
}

# Sample lines use RFC 5737 documentation addresses.
logtest 'Jan 01 00:00:00 GATEWAY-01 GATEWAY-01 [WAN_LAN-D-10021] DESCR="DROP WEB" IN=eth2 OUT=br2 MAC=02:00:00:00:00:55 SRC=203.0.113.55 DST=192.0.2.108 LEN=52 TOS=00 PREC=0x00 TTL=123 ID=1 DF PROTO=TCP SPT=63499 DPT=443 SEQ=1 ACK=0 WINDOW=65535 SYN URGP=0 MARK=1a0000 ' 'blocked traffic -> expect 110102 L5 alert'
logtest 'Jan 01 00:00:00 GATEWAY-01 GATEWAY-01 [WAN_LOCAL-D-2147483647] DESCR="[WAN_LOCAL]Block All Traffic" IN=eth2 OUT= MAC=02:00:00:00:00:55 SRC=203.0.113.99 DST=203.0.113.10 LEN=60 PROTO=TCP SPT=51000 DPT=445 ' 'default-deny -> expect 110102 L5 alert'
logtest 'Jan 01 00:00:00 GATEWAY-01 GATEWAY-01 [LAN_WAN-A-10027] DESCR="ALLOW OUT" IN=br40 OUT=eth2 MAC=02:00:00:00:00:55 SRC=192.0.2.50 DST=203.0.113.200 LEN=64 PROTO=TCP SPT=52131 DPT=443 ' 'allowed traffic -> expect 110101 L0 (suppressed)'

echo "validation complete."
