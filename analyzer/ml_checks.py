"""
Channel 11 — ML Risk Prediction.

Loads the RandomForestClassifier trained in ml/train_model.py on the real,
published Vrbancic et al. (2020) phishing dataset, extracts the same
feature set live from the URL being scanned, and folds the model's
phishing probability into the overall score as one more channel.

Reuses the WHOIS record and HTTP response the scorer already fetched for
the other channels — no duplicate network calls. If the model artifacts
are missing (training hasn't been run yet), this channel degrades
gracefully to a neutral score rather than crashing the whole scan.
"""
import os
import json
from urllib.parse import urlparse

from . import url_checks, domain_checks

try:
    import joblib
except ImportError:  # pragma: no cover
    joblib = None

HERE = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(os.path.dirname(HERE), "ml")
MODEL_PATH = os.path.join(ML_DIR, "model.joblib")
FEATURES_PATH = os.path.join(ML_DIR, "feature_list.json")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "shorte.st", "rebrand.ly",
}

_model = None
_feature_order = None
_load_attempted = False


def _load_model():
    """Lazy-load the model once per process."""
    global _model, _feature_order, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True
    if joblib is None:
        return
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
            _model = joblib.load(MODEL_PATH)
            with open(FEATURES_PATH) as f:
                _feature_order = json.load(f)
    except Exception:
        _model = None


def _count_vowels(s: str) -> int:
    return sum(1 for ch in s.lower() if ch in "aeiou")


def _domain_age_days(whois_record):
    """Best-effort age-in-days from a WHOIS record; None if unavailable."""
    if whois_record is None:
        return None
    try:
        from datetime import datetime, timezone
        created = domain_checks._first(whois_record.creation_date)
        if created is None:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).days
    except Exception:
        return None


def extract_features(url: str, https_channel: dict, cert_channel: dict, response=None, whois_record=None) -> dict:
    """Build the exact feature vector the model was trained on, reusing
    values already computed by the other channels wherever possible.

    The training dataset's qty_*_url / length_url features were extracted
    from the URL with its scheme prefix stripped (e.g. "example.com/path",
    not "https://example.com/path") — confirmed by qty_slash_url having a
    minimum of 0 across the dataset, which would be impossible if the
    "//" after "https:" were counted. We strip the scheme the same way
    before counting, so live features line up with what the model learned.
    """
    import re as _re

    stripped = _re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    is_ip = url_checks.is_ip_address(host)
    age_days = _domain_age_days(whois_record)
    redirect_hops = len(response.history) if response is not None else None
    ssl_valid = https_channel.get("status") == "pass" and cert_channel.get("status") == "pass"

    return {
        "qty_dot_url": stripped.count("."),
        "qty_hyphen_url": stripped.count("-"),
        "qty_underline_url": stripped.count("_"),
        "qty_slash_url": stripped.count("/"),
        "qty_questionmark_url": stripped.count("?"),
        "qty_equal_url": stripped.count("="),
        "qty_at_url": stripped.count("@"),
        "qty_and_url": stripped.count("&"),
        "qty_exclamation_url": stripped.count("!"),
        "length_url": len(stripped),
        "qty_tld_url": len(host.split(".")[-1]) if "." in host else 0,
        "domain_length": len(host),
        "qty_hyphen_domain": host.count("-"),
        "qty_vowels_domain": _count_vowels(host),
        "domain_in_ip": 1 if is_ip else 0,
        "time_domain_activation": age_days if age_days is not None else -1,
        "qty_redirects": redirect_hops if redirect_hops is not None else -1,
        "tls_ssl_certificate": 1 if ssl_valid else 0,
        "email_in_url": 1 if "@" in stripped else 0,
        "url_shortened": 1 if host.lower() in SHORTENERS else 0,
    }


def analyze_ml_risk(url: str, https_channel: dict, cert_channel: dict, response=None, whois_record=None) -> dict:
    """Channel 11 — ML Risk Prediction."""
    max_points = 15
    _load_model()

    if _model is None or _feature_order is None:
        return {
            "id": "ml_risk",
            "name": "ML Risk Prediction",
            "max_points": max_points,
            "points": round(max_points * 0.6),
            "status": "warn",
            "details": ["ML model not found — run `python ml/train_model.py` once to enable this channel."],
            "meta": {},
        }

    features = extract_features(url, https_channel, cert_channel, response=response, whois_record=whois_record)
    vector = [[features[name] for name in _feature_order]]

    try:
        phishing_probability = float(_model.predict_proba(vector)[0][1])
    except Exception as e:
        return {
            "id": "ml_risk",
            "name": "ML Risk Prediction",
            "max_points": max_points,
            "points": round(max_points * 0.6),
            "status": "warn",
            "details": [f"Model inference failed ({e})."],
            "meta": {},
        }

    safe_probability = 1 - phishing_probability
    points = round(max_points * safe_probability)

    if phishing_probability < 0.3:
        status = "pass"
        note = f"Model estimates a low phishing probability ({phishing_probability:.0%})."
    elif phishing_probability < 0.6:
        status = "warn"
        note = f"Model estimates a moderate phishing probability ({phishing_probability:.0%})."
    else:
        status = "fail"
        note = f"Model estimates a high phishing probability ({phishing_probability:.0%})."

    return {
        "id": "ml_risk",
        "name": "ML Risk Prediction",
        "max_points": max_points,
        "points": points,
        "status": status,
        "details": [
            note,
            "Prediction from a Random Forest trained on the Vrbancic et al. (2020) phishing dataset (58,645 real URLs).",
        ],
        "meta": {"phishing_probability": round(phishing_probability, 4), "features": features},
    }
