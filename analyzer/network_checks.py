"""
Live network checks: redirect behaviour and HTTP security response headers.

Covers Channel 08 (Redirect Behaviour) and Channel 09 (Security Headers).
Both checks make a single real HTTP request and are skipped gracefully
(with a neutral score) if the site cannot be reached.
"""
import requests

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

REQUEST_HEADERS = {
    "User-Agent": "SentryLink-Scanner/1.0 (+educational URL security assessment tool)"
}


def fetch(url: str, timeout: float = 6.0):
    """Single shared request so redirect + header checks don't double-hit the site."""
    return requests.get(
        url, headers=REQUEST_HEADERS, timeout=timeout, allow_redirects=True, verify=True
    )


def analyze_redirects(url: str, response=None, error=None) -> dict:
    """Channel 08 — Redirect Behaviour."""
    max_points = 10

    if error is not None:
        return {
            "id": "redirects",
            "name": "Redirect Behaviour",
            "max_points": max_points,
            "points": 5,
            "status": "warn",
            "details": [f"Site could not be reached to trace redirects ({error})."],
            "meta": {},
        }

    hops = len(response.history)
    final_url = response.url
    points = max_points
    issues = []

    if hops == 0:
        issues.append("No redirects — the submitted URL resolved directly.")
    elif hops <= 2:
        points -= 2
        issues.append(f"URL redirected {hops} time(s) to {final_url}.")
    else:
        points -= 6
        issues.append(f"URL redirected {hops} times before reaching {final_url}, an unusually long chain.")

    cross_scheme_downgrade = any(
        r.url.startswith("https://") for r in response.history
    ) and final_url.startswith("http://")
    if cross_scheme_downgrade:
        points -= 4
        issues.append("Redirect chain downgrades from HTTPS to HTTP.")

    points = max(points, 0)
    status = "pass" if points >= 8 else ("warn" if points >= 4 else "fail")

    return {
        "id": "redirects",
        "name": "Redirect Behaviour",
        "max_points": max_points,
        "points": points,
        "status": status,
        "details": issues,
        "meta": {"hops": hops, "final_url": final_url},
    }


def analyze_headers(url: str, response=None, error=None) -> dict:
    """Channel 09 — Security Response Headers."""
    max_points = 10

    if error is not None:
        return {
            "id": "security_headers",
            "name": "Security Response Headers",
            "max_points": max_points,
            "points": 5,
            "status": "warn",
            "details": [f"Site could not be reached to inspect response headers ({error})."],
            "meta": {},
        }

    present = [h for h in SECURITY_HEADERS if h in response.headers]
    missing = [h for h in SECURITY_HEADERS if h not in response.headers]

    points = round(max_points * (len(present) / len(SECURITY_HEADERS)))
    status = "pass" if points >= 8 else ("warn" if points >= 4 else "fail")

    details = []
    if present:
        details.append("Present: " + ", ".join(present) + ".")
    if missing:
        details.append("Missing: " + ", ".join(missing) + ".")

    return {
        "id": "security_headers",
        "name": "Security Response Headers",
        "max_points": max_points,
        "points": points,
        "status": status,
        "details": details,
        "meta": {"present": present, "missing": missing},
    }
