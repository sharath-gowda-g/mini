"""Train multiple models and save the best one (renamed from train_best_model.py)."""
import os
import sys
import math
import re
import types
from typing import Dict, Callable

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

try:
    from xgboost import XGBClassifier
    _HAS_XGBOOST = True
except Exception:
    XGBClassifier = None
    _HAS_XGBOOST = False

# File paths
NORMAL_PATH = os.path.join("data", "normal_1500_queries.csv")
SUSPICIOUS_PATH = os.path.join("data", "suspicious_1500_queries.csv")
BEST_MODEL_PATH = "best_dns_model.pkl"

# Import the feature extraction function from the shared module
from features.dns_features import extract_features


def train_and_evaluate(models: Dict[str, object], X_train, X_test, y_train, y_test):
    results = {}
    for name, model in models.items():
        if model is None:
            results[name] = {"trained": False, "accuracy": None, "report": "skipped (not available)"}
            continue

        print(f"Training {name}...")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        acc = float(accuracy_score(y_test, y_pred))
        report = classification_report(y_test, y_pred)
        results[name] = {"trained": True, "accuracy": acc, "report": report, "model": model}
        print(f"{name} accuracy: {acc:.4f}")

    return results


def select_best(results: Dict[str, dict]):
    best_name = None
    best_acc = -1.0
    best_model = None
    for name, r in results.items():
        if not r.get("trained"):
            continue
        acc = r.get("accuracy", 0.0)
        if acc is None:
            continue
        if acc > best_acc:
            best_acc = acc
            best_name = name
            best_model = r.get("model")
    return best_name, best_model, best_acc


def main():
    print("Using feature-extraction from features/dns_features.py...")

    # Load CSVs
    print("Loading datasets...")
    normal_df = pd.read_csv(NORMAL_PATH)
    suspicious_df = pd.read_csv(SUSPICIOUS_PATH)

    if "label" in normal_df.columns:
        normal_df = normal_df[normal_df["label"] == 0]
    else:
        normal_df["label"] = 0

    if "label" in suspicious_df.columns:
        suspicious_df = suspicious_df[suspicious_df["label"] == 1]
    else:
        suspicious_df["label"] = 1

    df = pd.concat([normal_df, suspicious_df], ignore_index=True)

    if "qname" not in df.columns:
        raise RuntimeError("Input CSVs must contain a 'qname' column")
    df["qname"] = df["qname"].fillna("")

    print(f"Total dataset size after merge: {len(df)}")

    X = extract_features(df)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, max_depth=15, min_samples_leaf=5,
            min_samples_split=10, random_state=42, class_weight="balanced", n_jobs=-1
        ),
        "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric="logloss") if _HAS_XGBOOST else None,
        "LogisticRegression": LogisticRegression(solver="liblinear", class_weight="balanced", max_iter=1000)
    }

    results = train_and_evaluate(models, X_train, X_test, y_train, y_test)

    for name, r in results.items():
        print("\n", "=" * 40)
        print(f"Model: {name}")
        if r.get("trained"):
            print(f"Accuracy: {r['accuracy']:.4f}")
            print("Classification Report:\n", r["report"])
        else:
            print(r.get("report", "skipped"))

    best_name, best_model, best_acc = select_best(results)
    if best_name is None:
        print("No trained models available to save. Ensure required packages are installed.")
        sys.exit(1)

    joblib.dump(best_model, BEST_MODEL_PATH)
    print(f"\n✅ Best model: {best_name} (accuracy={best_acc:.4f}). Saved to {BEST_MODEL_PATH}")

    summary = []
    for name, r in results.items():
        summary.append({"model": name, "accuracy": r.get("accuracy")})
    summary_df = pd.DataFrame(summary).sort_values(by="accuracy", ascending=False)
    print("\nModel comparison:")
    print(summary_df.to_string(index=False))


if __name__ == "__main__":
    main()
