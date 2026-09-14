"""
Trains the SentryLink ML risk-prediction channel on a real, published
academic dataset:

    G. Vrbancic, I. Fister Jr., V. Podgorelec.
    "Datasets for Phishing Websites Detection."
    Data in Brief, Vol. 33, 2020. DOI: 10.1016/j.dib.2020.106438
    https://github.com/GregaVrbancic/Phishing-Dataset  (dataset_small.csv)

Only features that SentryLink can realistically compute live for an
arbitrary submitted URL are used (lexical/structural URL features, TLS
validity, domain age, redirect count) — features that would require a
Google-index lookup or a paid API are intentionally excluded.

Run:  python ml/train_model.py
Produces: ml/model.joblib, ml/feature_list.json, ml/metrics.json
"""
import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "dataset_small.csv")
MODEL_PATH = os.path.join(HERE, "model.joblib")
FEATURES_PATH = os.path.join(HERE, "feature_list.json")
METRICS_PATH = os.path.join(HERE, "metrics.json")

# Features we can compute live from a submitted URL without a paid API.
FEATURE_COLUMNS = [
    "qty_dot_url",
    "qty_hyphen_url",
    "qty_underline_url",
    "qty_slash_url",
    "qty_questionmark_url",
    "qty_equal_url",
    "qty_at_url",
    "qty_and_url",
    "qty_exclamation_url",
    "length_url",
    "qty_tld_url",
    "domain_length",
    "qty_hyphen_domain",
    "qty_vowels_domain",
    "domain_in_ip",
    "time_domain_activation",
    "qty_redirects",
    "tls_ssl_certificate",
    "email_in_url",
    "url_shortened",
]
TARGET_COLUMN = "phishing"  # 1 = phishing, 0 = legitimate


def main():
    df = pd.read_csv(DATA_PATH)
    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=14,
        min_samples_leaf=3,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "dataset": "GregaVrbancic/Phishing-Dataset (dataset_small.csv)",
        "dataset_citation": "Vrbancic et al., Data in Brief, Vol. 33, 2020, DOI: 10.1016/j.dib.2020.106438",
        "total_rows": len(df),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "features_used": FEATURE_COLUMNS,
        "model": "RandomForestClassifier(n_estimators=200, max_depth=14, min_samples_leaf=3, class_weight='balanced')",
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_proba), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "feature_importances": dict(
            sorted(
                zip(FEATURE_COLUMNS, [round(v, 4) for v in model.feature_importances_]),
                key=lambda kv: kv[1],
                reverse=True,
            )
        ),
    }

    joblib.dump(model, MODEL_PATH)
    with open(FEATURES_PATH, "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(json.dumps({k: v for k, v in metrics.items() if k != "feature_importances"}, indent=2))
    print("\nTop features:")
    for name, imp in list(metrics["feature_importances"].items())[:8]:
        print(f"  {name}: {imp}")


if __name__ == "__main__":
    main()
