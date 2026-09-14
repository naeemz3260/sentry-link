# SentryLink — URL Security & Phishing Detection System

A web-based system that accepts a URL, runs it through 11 independent
checks (10 rule-based + 1 trained ML classifier), and returns a
transparent 0–100 risk score, a letter grade (A–F), a Safe / Suspicious /
High-Risk classification, per-check findings, and actionable
recommendations. Scans are stored so you can review or export past
results.

## 1. System Architecture

```
Browser (dashboard)
   │  fetch() JSON
   ▼
Flask app (app.py)  ───────────────┐
   │                                │
   ▼                                ▼
analyzer/scorer.py           database.py (SQLite)
   │  orchestrates 11 channels      │  scan history
   ▼                                │
analyzer/
  url_checks.py     – structure, subdomains, obfuscation
  ssl_checks.py     – HTTPS, certificate
  domain_checks.py  – shared WHOIS fetch, domain age, reputation/blacklist
  keyword_checks.py – phishing keywords, brand impersonation
  network_checks.py – live redirect + header inspection
  ml_checks.py      – loads ml/model.joblib, predicts phishing probability
ml/
  train_model.py    – trains the model from ml/dataset_small.csv
  dataset_small.csv – real dataset (see §4.1)
  model.joblib, feature_list.json, metrics.json – training output
```

- **Frontend**: server-rendered HTML (`templates/index.html`) + vanilla
  JS/CSS (`static/`). No frontend build step required.
- **Backend**: Flask, exposing a small JSON API (`/api/scan`, `/api/history`,
  `/api/history/<id>`, `/api/history/<id>/report`).
- **Database**: SQLite (`sentrylink.db`, created automatically on first run)
  storing every scan's inputs and full result JSON.
- **Analysis**: 10 rule-based, deterministic channels plus a trained ML
  classifier as an 11th channel (see §4 for full methodology). A single
  shared WHOIS lookup and a single shared HTTP fetch are reused across
  channels, so a scan never hits the target site or a WHOIS server twice.

## 2. The 11 Detection Channels

| # | Channel | Weight | What it checks |
|---|---------|--------|-----------------|
| 1 | URL Length & Structure | 10 | Excessive length, hyphen count, digit/letter mixing |
| 2 | HTTPS Enforcement | 15 | Whether the URL uses `https://` |
| 3 | SSL/TLS Certificate | 10 | Live handshake: issuer, expiry, validity |
| 4 | Domain Age (WHOIS) | 10 | Registration date; very new domains are penalized |
| 5 | Subdomain Depth | 5 | Number of subdomain levels |
| 6 | Obfuscation Indicators | 10 | Raw IP host, Punycode, `@` tricks, encoded chars |
| 7 | Suspicious Keywords & Brand Impersonation | 15 | Phishing keyword list + leetspeak-aware brand look-alike detection |
| 8 | Redirect Behaviour | 10 | Number of hops, HTTPS→HTTP downgrades |
| 9 | Security Response Headers | 10 | Presence of HSTS, CSP, X-Frame-Options, etc. |
| 10 | Domain Reputation | 5 | Local sample allow/blacklist (extension point for a live threat feed) |
| 11 | **ML Risk Prediction** | 15 | Random Forest's probability that the URL is phishing (§4) |

Weights sum to 115 across all 11 channels; the final percentage is
`earned / available × 100` (see §3), so adding the ML channel on top of
the 10 rule-based channels dilutes no single channel unfairly — each
still contributes its stated share of the total. Every channel returns
partial credit, not just pass/fail, so the score reflects *degree* of
risk rather than a single failing check zeroing out the whole result.

## 3. Scoring, Grading, Classification

```
score = round( Σ(points earned) / Σ(max points) × 100 )

Grade:            A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60
Classification:   Safe/Low Risk ≥ 80 · Suspicious 50–79 · High Risk/Malicious < 50
```

Every channel is fully documented in `analyzer/scorer.py`
(`RECOMMENDATION_MAP`) and each module's docstring — nothing is an
unexplained magic number. Recommendations are generated dynamically from
whichever channels scored `warn` or `fail` on a given scan.

## 4. Machine Learning Component

### 4.1 Dataset

**"Datasets for Phishing Websites Detection"** — G. Vrbančič, I. Fister Jr.,
V. Podgorelec, *Data in Brief*, Vol. 33, 2020,
DOI: [10.1016/j.dib.2020.106438](https://doi.org/10.1016/j.dib.2020.106438).
A real, peer-reviewed, published dataset — not synthetic data — retrieved
from the authors' public repository:
`github.com/GregaVrbancic/Phishing-Dataset` (`dataset_small.csv`).

- **58,645 labelled instances**: 30,647 phishing (53%), 27,998 legitimate (47%)
- **111 pre-extracted lexical/structural/domain features per URL**, of which
  SentryLink uses the 20 described below
- Label column: `phishing` (`1` = phishing, `0` = legitimate)

### 4.2 Feature selection

The full dataset ships 111 features, several of which require a Google
index-status lookup or a paid ranking API that SentryLink has no key for.
SentryLink trains on the **20-feature subset it can compute live**, with
no headless browser and no paid API, reusing values the rule-based
channels already compute:

`qty_dot_url, qty_hyphen_url, qty_underline_url, qty_slash_url,
qty_questionmark_url, qty_equal_url, qty_at_url, qty_and_url,
qty_exclamation_url, length_url, qty_tld_url, domain_length,
qty_hyphen_domain, qty_vowels_domain, domain_in_ip,
time_domain_activation, qty_redirects, tls_ssl_certificate,
email_in_url, url_shortened`

**Calibration note**: the dataset's `qty_*_url` / `length_url` features
are computed on the URL with its scheme prefix stripped (confirmed
empirically — `qty_slash_url` has a minimum of 0 across the dataset,
which would be impossible if the `//` in `https://` were counted).
`analyzer/ml_checks.py` strips the scheme the same way before counting,
so live features match what the model actually learned.

### 4.3 Model & training

- **Model**: `RandomForestClassifier(n_estimators=200, max_depth=14, min_samples_leaf=3, class_weight="balanced")` (scikit-learn)
- **Split**: 80% train (46,916 rows) / 20% test (11,729 rows), stratified on the label
- **Script**: `ml/train_model.py` — re-run with `python ml/train_model.py` to retrain
- **Artifacts**: `ml/model.joblib` (trained model), `ml/feature_list.json` (expected feature order), `ml/metrics.json` (full evaluation)

### 4.4 Evaluation metrics (held-out 20% test set — 11,729 real URLs)

| Metric | Score |
|---|---|
| Accuracy | 92.3% |
| Precision | 92.8% |
| Recall | 92.5% |
| F1 score | 92.7% |
| ROC AUC | 97.9% |

Confusion matrix (rows = actual, columns = predicted):

|  | Predicted legitimate | Predicted phishing |
|---|---|---|
| **Actual legitimate** | 5,159 | 441 |
| **Actual phishing** | 458 | 5,671 |

Top feature importances (Gini importance from the trained forest):

| Feature | Importance |
|---|---|
| qty_slash_url | 33.0% |
| length_url | 24.7% |
| time_domain_activation | 17.5% |
| domain_length | 4.2% |
| qty_equal_url | 3.3% |
| qty_hyphen_url | 3.3% |
| qty_dot_url | 3.0% |
| *(remaining 13 features)* | < 3% each |

This lines up with domain intuition: how deep/long a URL's path is, the
raw URL length, and how recently the domain was registered are the three
strongest live-computable phishing signals in this dataset.

### 4.5 How it's used at runtime

`analyzer/ml_checks.py` extracts the 20 live features for the submitted
URL (reusing the same WHOIS record and HTTP response the rule-based
channels already fetched, so there's no duplicate network cost), feeds
them to the loaded model, and turns the predicted phishing probability
into points out of 15 for Channel 11. The model is a **cross-check
alongside** the 10 rule-based channels, not a replacement for them — if
the model can't be loaded, that channel degrades to a neutral score
instead of failing the whole scan.

## 5. Setup & Running

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000`. The SQLite database file is created
automatically on first run. The trained model ships in `ml/model.joblib`
— no need to retrain before running the app, though `python
ml/train_model.py` reproduces it from `ml/dataset_small.csv`.

**Requires internet access** to actually fetch pages, resolve SSL
certificates, and run WHOIS lookups — this is a live scanner, not a static
demo.

## 6. Testing

The project was tested with:
- **Known-safe URLs** (e.g. `wikipedia.org`) — expected grade A, ML channel
  agreeing with a low phishing probability.
- **Deliberately crafted suspicious URLs** — long hyphenated hosts,
  leetspeak brand names (`paypa1-secure-login...`), `@`-symbol tricks,
  plain-HTTP endpoints, freshly "registered" domains — expected grade F,
  ML channel agreeing with a high phishing probability.
- **Unreachable/malformed URLs** — verified the app degrades gracefully
  (neutral partial score + a clear message) instead of crashing.
- **API-level tests** — `/api/scan` input validation (empty URL), history
  CRUD, and JSON report export were exercised directly against the Flask
  test client.
- **ML held-out test set** — the 11,729-row stratified test split in §4.4,
  never seen during training.

`data/sample_blacklist.json` contains a small local, clearly-labelled sample
dataset used only to test the reputation channel end-to-end, in line with
the assignment's instruction to test "in a controlled and ethical manner."
No real third-party sites are scraped or attacked during testing.

## 7. Limitations & Future Improvements

- **WHOIS reliability**: some registrars rate-limit or redact WHOIS data
  (GDPR privacy proxies); the domain-age channel — and the ML channel's
  `time_domain_activation` feature — degrade to a neutral value rather
  than failing the whole scan when that happens.
- **Reputation channel** currently checks a local sample list only. For
  production use, swap `analyzer/domain_checks.analyze_reputation` to call a
  real feed (Google Safe Browsing API, PhishTank, VirusTotal).
- **No JavaScript rendering**: the scanner inspects the URL, TLS layer, and
  raw HTTP response — it does not execute page JavaScript, so JS-based
  redirect/cloaking tricks are not detected.
- **ML feature subset**: trained on 20 of the original 111 dataset
  features — the ones computable with no headless browser and no paid
  API. This trades a little theoretical accuracy for a model that
  actually runs on a URL submitted right now.
- **Single-user local SQLite** — fine for coursework/demo; a multi-user
  deployment would need per-account history and a hosted database.

## 8. Project Structure

```
sentrylink/
├── app.py                  Flask routes / API
├── database.py             SQLite persistence (scan history)
├── requirements.txt
├── data/
│   └── sample_blacklist.json
├── analyzer/
│   ├── url_checks.py
│   ├── ssl_checks.py
│   ├── domain_checks.py
│   ├── keyword_checks.py
│   ├── network_checks.py
│   ├── ml_checks.py
│   └── scorer.py
├── ml/
│   ├── train_model.py
│   ├── dataset_small.csv
│   ├── model.joblib
│   ├── feature_list.json
│   └── metrics.json
├── templates/
│   └── index.html
└── static/
    ├── css/style.css
    └── js/app.js
```

## 9. Deploying

### GitHub

```bash
cd sentrylink
git init
git add .
git commit -m "Initial commit — SentryLink URL security scanner"
git branch -M main
git remote add origin <your-empty-github-repo-url>
git push -u origin main
```

`.gitignore` excludes `ml/dataset_small.csv` (16 MB, only needed to
retrain) and `sentrylink.db` (regenerated automatically). The trained
model (`ml/model.joblib`) **is** committed — the app needs it at runtime.

### Railway

1. Push the repo to GitHub first (above).
2. On [railway.app](https://railway.app): **New Project → Deploy from GitHub repo** → select this repo.
3. Railway auto-detects Python via `requirements.txt` and `Procfile` (Nixpacks). No manual build config needed — `railway.json` in this repo pins the start command explicitly.
4. Once deployed, go to the service's **Settings → Networking → Generate Domain** to get a public URL.
5. **Persistence note**: Railway's default filesystem is ephemeral — `sentrylink.db` (scan history) resets on every redeploy/restart. For coursework this is fine; for persistent history, attach a **Railway Volume** (Settings → Volumes → mount at `/app/data`) and point `database.DB_PATH` in `database.py` at that mounted path.
6. No environment variables are required to run. `PORT` is provided automatically by Railway and read in `app.py`.
