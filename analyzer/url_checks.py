"""
URL structure & obfuscation checks.

Covers Channel 01 (URL Length & Structure) and part of Channel 06
(IP address / punycode / special-character obfuscation).
"""
import re
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_CHARS = ["@", "%00", "%20", "\\", "javascript:", "data:"]


def normalize_url(raw_url: str) -> str:
    """Add a scheme if the user pasted a bare domain."""
    raw_url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "http://" + raw_url
    return raw_url


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_structure(url: str) -> dict:
    """Channel 01 — URL Length & Structure."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    length = len(url)

    issues = []
    points = 10  # max points for this channel

    if length > 100:
        points -= 5
        issues.append(f"URL is unusually long ({length} characters).")
    elif length > 75:
        points -= 2
        issues.append(f"URL is longer than typical ({length} characters).")

    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        points -= 3
        issues.append(f"Domain contains {hyphen_count} hyphens, a common phishing pattern.")
    elif hyphen_count >= 1:
        points -= 1

    digit_letter_mix = bool(re.search(r"[a-z]\d|\d[a-z]", host.lower())) and any(c.isdigit() for c in host)
    if digit_letter_mix and hyphen_count >= 1:
        points -= 2
        issues.append("Domain mixes digits and letters in a way that can mimic a brand name.")

    points = max(points, 0)
    status = "pass" if points >= 8 else ("warn" if points >= 4 else "fail")

    return {
        "id": "url_structure",
        "name": "URL Length & Structure",
        "max_points": 10,
        "points": points,
        "status": status,
        "details": issues or ["URL length and structure look normal."],
        "meta": {"length": length, "host": host, "hyphens": hyphen_count},
    }


def analyze_subdomains(url: str) -> dict:
    """Channel 05 — Subdomain Depth."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    points = 5
    issues = []

    if is_ip_address(host):
        return {
            "id": "subdomain_depth",
            "name": "Subdomain Depth",
            "max_points": 5,
            "points": 5,
            "status": "pass",
            "details": ["Host is a raw IP address; subdomain analysis skipped."],
            "meta": {"labels": 0},
        }

    labels = host.split(".")
    # naive: strip known common TLD suffix patterns of 2 labels (e.g. co.uk)
    subdomain_count = max(len(labels) - 2, 0)

    if subdomain_count >= 4:
        points -= 4
        issues.append(f"Domain has {subdomain_count} subdomain levels, unusually deep.")
    elif subdomain_count >= 2:
        points -= 2
        issues.append(f"Domain has {subdomain_count} subdomain levels.")

    points = max(points, 0)
    status = "pass" if points >= 4 else ("warn" if points >= 2 else "fail")

    return {
        "id": "subdomain_depth",
        "name": "Subdomain Depth",
        "max_points": 5,
        "points": points,
        "status": status,
        "details": issues or ["Subdomain depth looks normal."],
        "meta": {"labels": subdomain_count},
    }


def analyze_obfuscation(url: str) -> dict:
    """Channel 06 — IP address / punycode / special-character obfuscation."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    points = 10
    issues = []

    if is_ip_address(host):
        points -= 6
        issues.append("Host is a raw IP address instead of a domain name.")

    if host.startswith("xn--") or ".xn--" in host:
        points -= 5
        issues.append("Domain uses Punycode (xn--), which can hide look-alike Unicode characters.")

    for token in SUSPICIOUS_CHARS:
        if token in url:
            points -= 3
            issues.append(f"URL contains a suspicious sequence: '{token}'.")

    if "@" in url.split("://", 1)[-1].split("/")[0]:
        points -= 5
        issues.append("URL contains an '@' before the host, a classic redirection trick.")

    points = max(points, 0)
    status = "pass" if points >= 8 else ("warn" if points >= 4 else "fail")

    return {
        "id": "obfuscation",
        "name": "Obfuscation Indicators",
        "max_points": 10,
        "points": points,
        "status": status,
        "details": issues or ["No IP-based hosting, punycode, or obfuscation tricks detected."],
        "meta": {},
    }
