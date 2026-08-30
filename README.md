# wazuh-unifi-detections

Custom Wazuh detection content and a prebuilt dashboard for ingesting **UniFi
gateway** firewall and threat logs into Wazuh SIEM/XDR. Decoders parse UniFi's
syslog format, rules turn blocked traffic and scan behavior into alerts (with
MITRE ATT&CK tagging), and the dashboard visualizes it.

<img width="1761" height="1165" alt="Screenshot_2026-08-16_01-28-27" src="https://github.com/user-attachments/assets/f4f82ac3-cba8-4f29-82ab-ef40139851f8" />


Built and validated against a UniFi Enterprise Fortress Gateway (Network 9.x)
and Wazuh 4.14.x. Published for anyone integrating UniFi with Wazuh.

## What's here

```
decoders/    UniFi syslog decoders (firewall traffic, CEF SIEM export, CoreDNS)
rules/       Detection rules: blocked traffic, scan/storm correlation, MITRE tags
dashboards/  Legacy raw-decoder and normalized EFG contract v1 dashboards (NDJSON)
lists/       CDB threat-list template (known-bad IPs) for rule 110123
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
5. Import the dashboard through Dashboards > Stack Management > Saved Objects > Import:
   - Direct raw UniFi syslog with this repository's `110xxx` decoders and rules: `dashboards/unifi-wan-threats.ndjson`.
   - Graylog-normalized `secdoc.unifi.efg.v1` events with `121xxx` rules: `dashboards/unifi-efg-contract-v1.ndjson`.
   Both reference the stock `wazuh-alerts-*` index pattern and overwrite dashboard ID `unifi-wan-threats`, so import only the dashboard matching the active parser contract.

## Detection coverage

- **Firewall blocks** (rule 110102): any UniFi-blocked flow becomes a level-5 alert.
- **Allowed traffic** (rule 110101): suppressed by design (level 0, archive-only)
  because allow volume is ~99% of firewall logs and near-zero signal.
- **Scan / block storms** (rule 110103): repeated blocks from one source in a
  short window escalate to level 10, tagged MITRE T1046 (Network Service Discovery).
- **CEF SIEM events** (rules 100100+): admin activity, client events, IPS/threat
  detections, with correlation rules for brute force, deauth, and repeated threats.
- **Extended threat rules** (110120-110124): management-plane touch attempts,
  port-forward abuse and probing storms, known-bad IP contact via CDB list, and
  external probes of high-risk service ports (SMB/RDP/Telnet/RPC). Edit the
  management CIDRs in rule 110120 for your environment before deploying.

## Geo mapping

The dashboard includes a country region map, a source-IP coordinate map, and an
IP-location listing table. These require GeoIP enrichment on the manager so alerts
carry `GeoLocation.*` fields (city, country, lat/lon). Modern Wazuh builds enrich
public IPs automatically; confirm with a quick check that `GeoLocation.location`
exists on recent alerts.

The normalized EFG contract dashboard aggregates `data.source_ip` and `data.destination_port`. Its Graylog-to-Wazuh bridge also emits transport alias `srcip=source_ip` so Wazuh can populate `GeoLocation.*`. The alias does not change the normalized event hash or semantic contract field.

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

Dual-licensed, **attribution required**: code/rules/decoders under [Apache License 2.0](LICENSE); docs/diagrams under [CC BY 4.0](LICENSE-docs). See [`LICENSING.md`](LICENSING.md) and [`NOTICE`](NOTICE). Credit: Lester E. Nichols III, secdoc.tech.

No warranty. Detection content is environment-specific; validate with `wazuh-logtest` against your own log samples before trusting it inline.
