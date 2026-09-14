"""
Domain age (WHOIS) and reputation/blacklist checks.

Covers Channel 04 (Domain Age) and Channel 10 (Domain Reputation).
"""
import os
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import whois  # python-whois
except ImportError:  # pragma: no cover
    whois = None

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
BLACKLIST_PATH = os.path.join(DATA_DIR, "sample_blacklist.json")


def _load_blacklist():
    try:
        with open(BLACKLIST_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"domains": [], "trusted": []}


def _first(value):
    """python-whois sometimes returns a list of dates; take the earliest."""
    if isinstance(value, list):
        value = [v for v in value if v is not None]
        return min(value) if value else None
    return value


def fetch_whois(host: str):
    """Single shared WHOIS lookup, reused by the domain-age and ML channels
    so a scan only hits the WHOIS server once per host."""
    if whois is None or not host:
        return None
    try:
        return whois.whois(host)
    except Exception:
        return None


def analyze_domain_age(url: str, record=None) -> dict:
    """Channel 04 — Domain Age via WHOIS. Accepts a pre-fetched record to
    avoid a second WHOIS lookup when the caller already has one."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    max_points = 10

    if whois is None:
        return {
            "id": "domain_age",
            "name": "Domain Age (WHOIS)",
            "max_points": max_points,
            "points": 5,
            "status": "warn",
            "details": ["python-whois is not installed; domain age could not be checked."],
            "meta": {},
        }

    try:
        if record is None:
            record = whois.whois(host)
        created = _first(record.creation_date)

        if created is None:
            return {
                "id": "domain_age",
                "name": "Domain Age (WHOIS)",
                "max_points": max_points,
                "points": 5,
                "status": "warn",
                "details": ["WHOIS record did not return a creation date (common for privacy-protected domains)."],
                "meta": {},
            }

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days

        points = max_points
        if age_days < 30:
            points = 0
            note = f"Domain was registered only {age_days} days ago — a strong phishing signal."
        elif age_days < 180:
            points = 3
            note = f"Domain is {age_days} days old, quite new."
        elif age_days < 365:
            points = 6
            note = f"Domain is under a year old ({age_days} days)."
        else:
            note = f"Domain is well-established ({age_days // 365} year(s) old)."

        status = "pass" if points >= 8 else ("warn" if points >= 4 else "fail")
        return {
            "id": "domain_age",
            "name": "Domain Age (WHOIS)",
            "max_points": max_points,
            "points": points,
            "status": status,
            "details": [note],
            "meta": {"age_days": age_days, "created": str(created)},
        }

    except Exception as e:
        return {
            "id": "domain_age",
            "name": "Domain Age (WHOIS)",
            "max_points": max_points,
            "points": 5,
            "status": "warn",
            "details": [f"WHOIS lookup failed or is rate-limited ({e})."],
            "meta": {},
        }


def analyze_reputation(url: str) -> dict:
    """Channel 10 — Domain Reputation / Blacklist (local sample dataset).

    In production this channel is the integration point for a real threat-intel
    feed (e.g. Google Safe Browsing, PhishTank, VirusTotal). See README.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    max_points = 5
    data = _load_blacklist()

    if any(host == d or host.endswith("." + d) for d in data.get("domains", [])):
        return {
            "id": "reputation",
            "name": "Domain Reputation",
            "max_points": max_points,
            "points": 0,
            "status": "fail",
            "details": ["Domain matches a known malicious entry in the local threat sample list."],
            "meta": {"source": "local sample blacklist"},
        }

    if any(host == d or host.endswith("." + d) for d in data.get("trusted", [])):
        return {
            "id": "reputation",
            "name": "Domain Reputation",
            "max_points": max_points,
            "points": max_points,
            "status": "pass",
            "details": ["Domain matches a known trusted entry in the local sample list."],
            "meta": {"source": "local sample allowlist"},
        }

    return {
        "id": "reputation",
        "name": "Domain Reputation",
        "max_points": max_points,
        "points": 4,
        "status": "pass",
        "details": ["No match in local threat-intel sample; not flagged by any known blacklist."],
        "meta": {"source": "local sample dataset (extend with a live API for production use)"},
    }
