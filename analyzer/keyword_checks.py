"""
Phishing keyword and brand-impersonation detection.

Covers Channel 07 (Suspicious Keywords & Brand Impersonation).
"""
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "billing", "invoice", "suspend", "unlock",
    "reactivate", "webscr", "recover", "support-center",
]

# A small set of frequently-impersonated brands. In each case we check whether
# the brand name appears in the URL *without* the host actually belonging to
# that brand's real domain — a strong sign of typosquatting / impersonation.
WATCHED_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com"],
    "netflix": ["netflix.com"],
    "bankofamerica": ["bankofamerica.com"],
    "whatsapp": ["whatsapp.com"],
    "instagram": ["instagram.com"],
}


def analyze_keywords(url: str) -> dict:
    """Channel 07 — Suspicious Keywords & Brand Impersonation."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    full_lower = url.lower()
    max_points = 15
    points = max_points
    issues = []

    hit_keywords = [k for k in PHISHING_KEYWORDS if k in full_lower]
    if hit_keywords:
        deduction = min(6, 2 * len(hit_keywords))
        points -= deduction
        issues.append(
            "Contains phishing-associated keyword(s): " + ", ".join(sorted(set(hit_keywords))) + "."
        )

    # Normalize common leetspeak/homoglyph substitutions before matching, so
    # tricks like "paypa1" or "micr0soft" are still caught.
    leet_map = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "4": "a", "7": "t"})
    normalized_host = host.translate(leet_map).replace("-", "").replace(".", "")

    impersonated = []
    for brand, real_domains in WATCHED_BRANDS.items():
        if brand in normalized_host:
            if not any(host == d or host.endswith("." + d) for d in real_domains):
                impersonated.append(brand)

    if impersonated:
        points -= 9
        issues.append(
            "Domain references brand name(s) "
            + ", ".join(impersonated)
            + " but does not match that brand's official domain — likely impersonation."
        )

    points = max(points, 0)
    status = "pass" if points >= 12 else ("warn" if points >= 6 else "fail")

    return {
        "id": "keywords_brand",
        "name": "Suspicious Keywords & Brand Impersonation",
        "max_points": max_points,
        "points": points,
        "status": status,
        "details": issues or ["No phishing-associated keywords or brand impersonation detected."],
        "meta": {"keywords_found": hit_keywords, "impersonated_brands": impersonated},
    }
