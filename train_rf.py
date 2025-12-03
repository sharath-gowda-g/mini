"""Train a RandomForest model (renamed from `train_model.py`)."""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

MODEL_PATH = "dns_model.pkl"

# Import feature extraction helpers and data loader
from features.dns_features import extract_features
from data_loader import load_archive_datasets

# -------------------------
# Load data from archive folder
# -------------------------
print("Loading datasets from archive folder...")
df = load_archive_datasets()

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
