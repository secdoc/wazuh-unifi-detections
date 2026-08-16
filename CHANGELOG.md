# Changelog

All notable changes to the UniFi to Wazuh detection content and dashboard.

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
