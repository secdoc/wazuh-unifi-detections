#!/usr/bin/env python3
"""Sanitize Wazuh UniFi artifacts for public release.

Owner-specific replacements must be supplied from an untracked JSON file through
SANITIZE_MAP_FILE. The public repository contains policy and generic detection,
not the owner's addresses, hostnames, account names, or credential fragments.
"""

import glob
import ipaddress
import json
import os
import re
import sys

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![0-9])")
INTERNAL_DNS = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:home|internal)\b")
ALLOWED_PRIVATE_CIDRS = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"
))
TEXT_SUFFIXES = (".conf", ".json", ".md", ".ndjson", ".txt", ".xml")


def load_replacements():
    path = os.environ.get("SANITIZE_MAP_FILE")
    if not path:
        return {}
    with open(path, encoding="utf-8") as handle:
        values = json.load(handle)
    if not isinstance(values, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in values.items()
    ):
        raise SystemExit("SANITIZE_MAP_FILE must contain a JSON object of string replacements")
    return values


def sanitize_text(text, replacements):
    for source, replacement in replacements.items():
        text = text.replace(source, replacement)
    text = MAC.sub("00:11:22:33:44:55", text)
    text = EMAIL.sub("user@example.com", text)
    return text


def is_disallowed_private_address(token):
    if token in ALLOWED_PRIVATE_CIDRS:
        return False
    try:
        return ipaddress.ip_interface(token).ip.is_private
    except ValueError:
        return False


def scan_text(text):
    findings = []
    if INTERNAL_DNS.search(text):
        findings.append("internal DNS name")
    if any(match.group(0) != "00:11:22:33:44:55" for match in MAC.finditer(text)):
        findings.append("MAC address")
    for match in IPV4.finditer(text):
        token = match.group(0)
        try:
            address = ipaddress.ip_interface(token).ip
        except ValueError:
            continue
        if any(address in network for network in DOCUMENTATION_NETWORKS):
            continue
        if token not in ALLOWED_PRIVATE_CIDRS and address.is_private:
            findings.append("specific private IPv4 address")
            break
    return findings


def iter_files(root):
    script = os.path.realpath(__file__)
    mapping = os.path.realpath(os.environ.get("SANITIZE_MAP_FILE", ""))
    for path in glob.glob(f"{root}/**/*", recursive=True):
        real_path = os.path.realpath(path)
        if not os.path.isfile(path) or real_path in {script, mapping}:
            continue
        if ".git/" in path or not path.endswith(TEXT_SUFFIXES):
            continue
        yield path


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    replacements = load_replacements()
    changed = 0
    for path in iter_files(root):
        original = open(path, encoding="utf-8", errors="ignore").read()
        sanitized = sanitize_text(original, replacements)
        if sanitized != original:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(sanitized)
            changed += 1
    leaks = []
    for path in iter_files(root):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for finding in scan_text(text):
            leaks.append((path, finding))
    print(f"files changed: {changed}")
    if leaks:
        print("LEAK DETECTED, aborting:")
        for path, finding in leaks:
            print(f"  {path}: {finding}")
        return 1
    print("privacy check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
