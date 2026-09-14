"""
Orchestrates all 10 detection channels, computes the final score, grade,
classification, and human-readable recommendations.
"""
import time
import requests

from . import url_checks, ssl_checks, domain_checks, keyword_checks, network_checks, ml_checks


RECOMMENDATION_MAP = {
    "https_enforcement": "Only proceed if the address bar shows HTTPS. Avoid entering credentials on plain HTTP sites.",
    "ssl_certificate": "Check that the certificate is valid and issued by a recognized authority before trusting the connection.",
    "url_structure": "Be cautious of very long URLs or ones with excessive hyphens — they're often used to disguise a fake domain.",
    "subdomain_depth": "Deeply nested subdomains can be used to make a fake site look like part of a trusted domain.",
    "obfuscation": "Never trust a link containing an '@' symbol, an IP address, or Punycode characters instead of a normal domain.",
    "domain_age": "Treat very recently registered domains with extra caution, especially if asking for sensitive data.",
    "keywords_brand": "Double-check the exact domain when a page claims to be a well-known brand — attackers rely on look-alike names.",
    "redirects": "Be wary of pages that redirect multiple times before landing on the final content.",
    "security_headers": "Missing security headers don't confirm malice but indicate weaker defenses against common web attacks.",
    "reputation": "Cross-check unfamiliar domains against a threat-intelligence source before entering any data.",
    "ml_risk": "Treat the ML estimate as a second opinion, not a verdict — combine it with the rule-based findings above.",
}


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def classification_for_score(score: int) -> str:
    if score >= 80:
        return "Safe / Low Risk"
    if score >= 50:
        return "Suspicious"
    return "High Risk / Malicious"


def grade_tagline(grade: str) -> str:
    return {
        "A": "Strong security posture across the board.",
        "B": "Solid, with a little room to improve.",
        "C": "Several weak points worth addressing.",
        "D": "Multiple significant risk indicators found.",
        "F": "Strong phishing/risk signals — avoid entering any data.",
    }[grade]


def run_full_scan(raw_url: str) -> dict:
    started = time.time()
    submitted_url = raw_url.strip()
    normalized_url = url_checks.normalize_url(submitted_url)

    # Single shared network fetch for redirect + header channels.
    response, fetch_error = None, None
    try:
        response = network_checks.fetch(normalized_url)
    except requests.exceptions.RequestException as e:
        fetch_error = str(e)

    final_url = response.url if response is not None else normalized_url

    # Single shared WHOIS lookup, reused by both the domain-age channel and
    # the ML channel so a scan only hits the WHOIS server once per host.
    from urllib.parse import urlparse as _urlparse
    host = _urlparse(normalized_url).hostname or ""
    whois_record = domain_checks.fetch_whois(host)

    https_channel = ssl_checks.analyze_https(normalized_url)
    cert_channel = ssl_checks.analyze_certificate(normalized_url)

    channels = [
        url_checks.analyze_structure(normalized_url),
        https_channel,
        cert_channel,
        domain_checks.analyze_domain_age(normalized_url, record=whois_record),
        url_checks.analyze_subdomains(normalized_url),
        url_checks.analyze_obfuscation(normalized_url),
        keyword_checks.analyze_keywords(normalized_url),
        network_checks.analyze_redirects(normalized_url, response=response, error=fetch_error),
        network_checks.analyze_headers(normalized_url, response=response, error=fetch_error),
        domain_checks.analyze_reputation(normalized_url),
        ml_checks.analyze_ml_risk(
            normalized_url, https_channel, cert_channel, response=response, whois_record=whois_record
        ),
    ]

    total_score = sum(c["points"] for c in channels)
    total_max = sum(c["max_points"] for c in channels)
    # Normalize defensively in case max weights ever drift from 100.
    score = round(total_score / total_max * 100) if total_max else 0
    grade = grade_for_score(score)
    classification = classification_for_score(score)

    recommendations = []
    for c in channels:
        if c["status"] in ("warn", "fail"):
            rec = RECOMMENDATION_MAP.get(c["id"])
            if rec:
                recommendations.append({"channel": c["name"], "recommendation": rec})

    if not recommendations:
        recommendations.append({
            "channel": "Overall",
            "recommendation": "No significant issues found. Still verify the domain matches who you expect before entering sensitive data.",
        })

    elapsed_ms = round((time.time() - started) * 1000)

    return {
        "submitted_url": submitted_url,
        "normalized_url": normalized_url,
        "final_url": final_url,
        "score": score,
        "grade": grade,
        "tagline": grade_tagline(grade),
        "classification": classification,
        "channels": channels,
        "channel_count": len(channels),
        "recommendations": recommendations,
        "fetch_error": fetch_error,
        "scan_time_ms": elapsed_ms,
    }
