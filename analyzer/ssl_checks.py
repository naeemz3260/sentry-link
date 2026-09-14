"""
HTTPS enforcement & SSL/TLS certificate checks.

Covers Channel 02 (HTTPS Enforcement) and Channel 03 (SSL/TLS Certificate).
"""
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


def analyze_https(url: str) -> dict:
    """Channel 02 — HTTPS Enforcement."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    points = 15
    issues = []

    if scheme != "https":
        points = 0
        issues.append("Site is served over plain HTTP; traffic is not encrypted.")
    else:
        issues.append("Site is served over HTTPS.")

    status = "pass" if points == 15 else "fail"
    return {
        "id": "https_enforcement",
        "name": "HTTPS Enforcement",
        "max_points": 15,
        "points": points,
        "status": status,
        "details": issues,
        "meta": {"scheme": scheme},
    }


def analyze_certificate(url: str, timeout: float = 5.0) -> dict:
    """Channel 03 — SSL/TLS Certificate validity, expiry, and issuer."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    max_points = 10

    if parsed.scheme.lower() != "https" or not host:
        return {
            "id": "ssl_certificate",
            "name": "SSL/TLS Certificate",
            "max_points": max_points,
            "points": 0,
            "status": "fail",
            "details": ["No HTTPS connection to inspect a certificate on."],
            "meta": {},
        }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days

        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_parts.get("organizationName", issuer_parts.get("commonName", "Unknown"))

        points = max_points
        issues = [f"Valid certificate issued by {issuer}, expiring in {days_left} days."]

        if days_left < 0:
            points = 0
            issues = [f"Certificate expired {abs(days_left)} days ago."]
        elif days_left < 15:
            points -= 5
            issues.append("Certificate is close to expiry.")

        status = "pass" if points >= 8 else ("warn" if points >= 4 else "fail")
        return {
            "id": "ssl_certificate",
            "name": "SSL/TLS Certificate",
            "max_points": max_points,
            "points": max(points, 0),
            "status": status,
            "details": issues,
            "meta": {"issuer": issuer, "days_left": days_left},
        }

    except ssl.SSLCertVerificationError as e:
        return {
            "id": "ssl_certificate",
            "name": "SSL/TLS Certificate",
            "max_points": max_points,
            "points": 0,
            "status": "fail",
            "details": [f"Certificate verification failed: {e.verify_message if hasattr(e, 'verify_message') else str(e)}"],
            "meta": {},
        }
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {
            "id": "ssl_certificate",
            "name": "SSL/TLS Certificate",
            "max_points": max_points,
            "points": 3,
            "status": "warn",
            "details": [f"Could not connect to inspect the certificate ({e})."],
            "meta": {},
        }
