# UniFi to Wazuh Integration Guide

Validated against UniFi Network 9.x (Enterprise Fortress Gateway) and Wazuh 4.14.x.
Version-specific paths marked (v); re-verify on newer releases.

## 1. Sender: UniFi gateway

Settings > Control Plane > Integrations > Activity Logging / SIEM Server (v).
Set the Wazuh manager IP and UDP port 514. UniFi is UDP-only for syslog (v).
Enable content categories deliberately:

- `firewall_default_policy` / firewall block logging: the high-value security
  events. On zone-based firewall builds, enable the **Log** toggle on the
  zone-matrix default Block for the zone pairs you care about (WAN ingress/egress
  first). Pair-default logging is UI-only on current builds; the per-policy
  `logging` flag is API-writable on custom rules but not on synthetic
  pair-defaults.
- `security_detections`: IPS/IDS alerts.

Multi-interface caveat: the gateway sources syslog from the interface routing
toward the collector, not necessarily its management IP. Confirm the real source
with `tcpdump -i any -n udp port 514` on the manager before setting allowed-ips.

## 2. Receiver: Wazuh manager

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.0.0/16</allowed-ips>  <!-- must cover the gateway SOURCE ip -->
</remote>
```
Restart wazuh-manager. Confirm arrival with tcpdump, then confirm decode with
wazuh-logtest.

## 3. Log format and the DESCR dependency

UniFi firewall syslog lines look like:

```
Jan 01 00:00:00 GATEWAY-01 GATEWAY-01 [WAN_LAN-D-10021] DESCR="DROP WEB" IN=eth2 OUT=br2 MAC=... SRC=203.0.113.55 DST=192.0.2.108 ... PROTO=TCP SPT=63499 DPT=443 ...
```

The `unifi-traffic` decoder prematch REQUIRES a `DESCR="..."` field
(`[<tag>] DESCR="<text>" IN=`). This holds for named rules AND synthetic
pair-defaults (e.g. `[WAN_LOCAL-D-2147483647] DESCR="[WAN_LOCAL]Block All Traffic"`).

Decode/alert behavior by line shape:

| Line shape | Decoder | Rule | Alert |
|---|---|---|---|
| `[TAG] DESCR="name" IN=...` | unifi-traffic | 110102 L5 | YES |
| `[TAG] DESCR="" IN=...` | unifi-traffic | 110100 L0 | no (grouping) |
| `[TAG] IN=...` (no DESCR) | NONE | none | invisible |

If your build emits firewall lines without DESCR, add a sibling child decoder to
`unifi-traffic` whose regex does not require DESCR, ordered AFTER the
DESCR-bearing children (sibling decoders are first-match-wins). Validate with
wazuh-logtest before restart.

## 4. Rule map

| Rule | Level | Fires on | MITRE |
|---|---|---|---|
| 110100 | 0 | UniFi firewall traffic (grouping) | - |
| 110101 | 0 | Allowed traffic (suppressed, archive-only) | - |
| 110102 | 5 | Blocked traffic | - |
| 110103 | 10 | Repeated blocks from one source (scan/storm) | T1046 |
| 100100+ | var | CEF SIEM export: admin, client, IPS/threat events | various |

## 5. Validation loop

1. Trigger a known block (attempt a denied port from a client).
2. `wazuh-logtest` a captured line: confirm decoder + rule fire.
3. Dashboard: filter `rule.groups: firewall_block` or open the UniFi WAN Threats
   dashboard.
4. Only then tune levels and correlation thresholds.

## 6. Notes

- `archives.json` (raw pre-alert log store) is NOT readable via the Wazuh Server
  API; only `ossec.log` is. To capture a raw line you need shell on the manager,
  or query `wazuh-archives-*` on the indexer (9200).
- `/logtest` over the Server API validates any line you hand it, enough to build
  or fix a decoder remotely without shell.
