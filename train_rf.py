"""Train a RandomForest model (renamed from `train_model.py`)."""

import pandas as pd
import numpy as np
import math
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# -------------------------
# File paths
# -------------------------
normal_path = "data/normal_1500_queries.csv"
suspicious_path = "data/suspicious_1500_queries.csv"
MODEL_PATH = "dns_model.pkl"

# Use feature extraction helpers from features.dns_features
from features.dns_features import extract_features

# -------------------------
# Load data from CSV files
# -------------------------
normal_df = pd.read_csv(normal_path)
suspicious_df = pd.read_csv(suspicious_path)

if "label" in normal_df.columns:
    normal_df = normal_df[normal_df["label"] == 0]
else:
    normal_df["label"] = 0

if "label" in suspicious_df.columns:
    suspicious_df = suspicious_df[suspicious_df["label"] == 1]
else:
    suspicious_df["label"] = 1

df = pd.concat([normal_df, suspicious_df], ignore_index=True)
df.dropna(subset=["qname"], inplace=True)
df.reset_index(drop=True, inplace=True)

print(f"Loaded {len(normal_df)} normal queries and {len(suspicious_df)} suspicious queries")
print(f"Total dataset size: {len(df)}")
print(f"Label distribution: {df['label'].value_counts()}")

X = extract_features(df)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_leaf=5,
    min_samples_split=10,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))
print("✅ Accuracy:", accuracy_score(y_test, y_pred))

joblib.dump(model, MODEL_PATH)
print(f"\n✅ Model trained and saved as {MODEL_PATH}")
