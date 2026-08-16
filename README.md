# wazuh-unifi-detections

Custom Wazuh detection content and a prebuilt dashboard for ingesting **UniFi
gateway** firewall and threat logs into Wazuh SIEM/XDR. Decoders parse UniFi's
syslog format, rules turn blocked traffic and scan behavior into alerts (with
MITRE ATT&CK tagging), and the dashboard visualizes it.

Built and validated against a UniFi Enterprise Fortress Gateway (Network 9.x)
and Wazuh 4.14.x. Published for anyone integrating UniFi with Wazuh.

## What's here

```
decoders/    UniFi syslog decoders (firewall traffic, CEF SIEM export, CoreDNS)
rules/       Detection rules: blocked traffic, scan/storm correlation, MITRE tags
dashboards/  "UniFi WAN Threats" dashboard (OpenSearch Dashboards saved-objects NDJSON)
docs/        Integration guide: sender config, decoder logic, rule map
scripts/     sanitize.py (public-release scrubber), validate.sh (logtest checks)
```

## Install

1. Copy decoders to `/var/ossec/etc/decoders/` and rules to `/var/ossec/etc/rules/`
   on the Wazuh manager.
2. Point your UniFi gateway's syslog/SIEM export at the manager (UDP 514). See
   `docs/integration.md`.
3. Validate before restart:
   ```
   /var/ossec/bin/wazuh-logtest    # paste a real UniFi log line; confirm decode + rule
   ```
4. Restart: `systemctl restart wazuh-manager`
5. Import the dashboard: Dashboards > Stack Management > Saved Objects > Import,
   select `dashboards/unifi-wan-threats.ndjson`. It references the stock
   `wazuh-alerts-*` index pattern.

## Detection coverage

- **Firewall blocks** (rule 110102): any UniFi-blocked flow becomes a level-5 alert.
- **Allowed traffic** (rule 110101): suppressed by design (level 0, archive-only)
  because allow volume is ~99% of firewall logs and near-zero signal.
- **Scan / block storms** (rule 110103): repeated blocks from one source in a
  short window escalate to level 10, tagged MITRE T1046 (Network Service Discovery).
- **CEF SIEM events** (rules 100100+): admin activity, client events, IPS/threat
  detections, with correlation rules for brute force, deauth, and repeated threats.

## Sanitization / privacy

This repo is public and scrubbed. `scripts/sanitize.py` runs before every commit
and redacts owner-identifying data: our public/WAN IPs, internal hostnames, local
domains, emails, MACs, and controller UUIDs. It is committed so the process is
auditable. What is deliberately KEPT: RFC1918 CIDRs used as generic matchers
(they are universal), and third-party IPs that appear as threat context. Example
addresses use the RFC 5737 documentation ranges (192.0.2.0/24, 203.0.113.0/24).

If you fork this for your own environment, replace the example addresses with
yours and re-run the sanitizer before publishing.

## License

MIT. No warranty. Detection content is environment-specific; validate with
`wazuh-logtest` against your own log samples before trusting it inline.
