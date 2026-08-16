# Changelog

All notable changes to the UniFi to Wazuh detection content and dashboard.

## 2026-08-16 - Extended detections + geo mapping

### Added
- `rules/unifi_threat_rules.xml` (custom IDs 110120-110124):
  - 110120 (L10): blocked attempt to the management plane (T1021).
  - 110121 (L7): blocked traffic to a published port-forward/DNAT (T1190).
  - 110122 (L12): repeated port-forward probing storm (T1190).
  - 110123 (L12): internal host blocked reaching a known-bad IP via CDB list (T1071).
  - 110124 (L8): blocked probe of high-risk service ports SMB/RDP/Telnet/RPC (T1046).
- `lists/unifi-malicious-ip.example`: CDB threat-list template for rule 110123.
- Dashboard geo panels: region map (blocked sources by country), coordinate map
  (source IP geo-points), and an IP-location listing table (IP, city, country, count).
  Requires GeoIP enrichment on the manager (GeoLocation.* fields on alerts).

### Notes
- Rule 110120 ships with placeholder management CIDRs (10.0.0-2.x). EDIT them to
  your own management subnets before deploying.
- Deploy detections by placing the rule file in `/var/ossec/etc/rules/` and
  registering the CDB list in `ossec.conf` `<ruleset>`, then restart the manager.
  The Wazuh 4.14.5 Server API `PUT /rules/files` endpoint returned a spurious
  XML-syntax error (code 1113) on all uploads including known-valid files, so
  file-based deployment is the reliable path on that build. CDB list and dashboard
  imports via API worked normally.

## 2026-08-16 - Initial public release

### Added
- UniFi syslog decoders: firewall traffic (`unifi-traffic`), CEF SIEM export
  (`unifi-cef`), and CoreDNS (`unifi-coredns`).
- Detection rules:
  - 110100/110101/110102: firewall traffic grouping, allow-suppression, block alerting.
  - 110103: repeated-block scan/storm correlation (level 10, MITRE T1046).
  - 100100+: CEF SIEM event rules (admin, client, IPS/threat) with correlation
    for brute force, deauth, and repeated threats.
- "UniFi WAN Threats" dashboard (OpenSearch Dashboards saved-objects): top
  blocked sources, blocks over time, top targeted ports, alerts by rule, and a
  scan/storm detection metric. References the stock `wazuh-alerts-*` index pattern.
- `scripts/sanitize.py`: public-release scrubber (redacts owner IPs, hostnames,
  domains, emails, MACs, UUIDs; keeps RFC1918 matchers and third-party threat IPs).
- `scripts/validate.sh`: Server-API logtest validation of decoders/rules.
- `docs/integration.md`: sender config, the DESCR decoder dependency, rule map.

### Sanitization
- All content scrubbed via `scripts/sanitize.py`; canary check passed (no
  owner-identifying tokens). Example addresses use RFC 5737 documentation ranges.
