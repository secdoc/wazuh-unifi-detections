#!/usr/bin/env python3
"""Sanitize Wazuh UniFi detection + dashboard artifacts for PUBLIC release.

Policy (agreed with owner):
- REDACT owner-identifying infrastructure: our public/WAN IPs, Tailscale/CGNAT
  addresses, internal hostnames, local domains, emails, MACs, controller UUIDs.
- KEEP third-party IPs (attackers, public DNS, threat sources) — they are threat
  context, not owner PII, and their public value is the point of sharing.
- KEEP RFC1918 CIDRs used as generic matchers (10/8, 172.16/12, 192.168/16) —
  universal, non-identifying.
- REDACT specific RFC1918 host addresses that map to our named segments only if
  they reveal internal layout in a sample (replaced with 192.0.2.x doc range).

Run before every commit. Idempotent. Exit non-zero if a known-secret token
survives (defense in depth).
"""
import re, sys, os, glob

# --- owner-identifying values to redact (EXACT) ---
OWNER_PUBLIC_IPS = {
    "71.128.4.186": "203.0.113.10",     # WAN primary  -> TEST-NET-3 doc range
    "71.128.4.1":   "203.0.113.1",      # WAN gateway
    "100.127.125.129": "203.0.113.20",  # CGNAT/secondary WAN
    "100.96.0.2":   "100.64.0.2",       # Tailscale node -> generic CGNAT shared range
}
# internal host samples that expose layout (map to 192.0.2.x TEST-NET-1)
OWNER_PRIV_HOSTS = {
    "192.168.2.243": "192.0.2.243",     # wazuh host
    "192.168.88.1":  "192.0.2.1",       # gateway mgmt
    "192.168.2.1":   "192.0.2.1",
    "192.168.88.55": "192.0.2.55",      # admin workstation
    "192.168.2.108": "192.0.2.108",     # NPM / port-forward target
}
TOKENS = {
    r"VOID-EFG": "GATEWAY-01",
    r"wazuh-debian13-lab-kvm-svr": "wazuh-manager",
    r"technitium-lab-debian13-kvm-svr": "dns-server",
    r"graylog-debian13-lab-kvm-svr": "graylog-server",
    r"ESSEXLAB": "LAB",
    r"secdoc": "example",
    r"\.secdoc\.home": ".example.local",
    r"\.secdoc\.tech": ".example.com",
    r"56358e39-74b3-4853-baba-f5b7fcd57893": "00000000-0000-0000-0000-000000000000",
}
EMAIL = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
MAC = re.compile(r'\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b')

# leak canaries: if ANY of these survive, fail the run
CANARIES = list(OWNER_PUBLIC_IPS) + list(OWNER_PRIV_HOSTS) + [
    "VOID-EFG","secdoc.home","secdoc.tech","wazuh-debian13"]

def sanitize_text(t):
    for ip, repl in {**OWNER_PUBLIC_IPS, **OWNER_PRIV_HOSTS}.items():
        t = t.replace(ip, repl)
    for pat, repl in TOKENS.items():
        t = re.sub(pat, repl, t)
    t = MAC.sub("00:11:22:33:44:55", t)
    t = EMAIL.sub("user@example.com", t)
    return t

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    changed = 0
    for f in glob.glob(f"{root}/**/*", recursive=True):
        if not os.path.isfile(f): continue
        if any(seg in f for seg in (".git/","/scripts/sanitize.py")): continue
        if not f.endswith((".xml",".ndjson",".md",".json",".conf",".txt")): continue
        orig = open(f, encoding="utf-8", errors="ignore").read()
        new = sanitize_text(orig)
        if new != orig:
            open(f,"w").write(new); changed += 1
            print(f"  sanitized {f}")
    # canary check
    leaks = []
    for f in glob.glob(f"{root}/**/*", recursive=True):
        if not os.path.isfile(f) or ".git/" in f or "sanitize.py" in f: continue
        if not f.endswith((".xml",".ndjson",".md",".json",".conf",".txt")): continue
        txt = open(f, encoding="utf-8", errors="ignore").read()
        for c in CANARIES:
            if c in txt: leaks.append((f, c))
    print(f"\nfiles changed: {changed}")
    if leaks:
        print("LEAK DETECTED — aborting:")
        for f,c in leaks: print(f"  {c} still in {f}")
        sys.exit(1)
    print("canary check: PASS (no owner-identifying tokens remain)")

if __name__ == "__main__":
    main()
