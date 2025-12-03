"""Train all candidate models and select the best one (renamed from train_all_models.py)."""
from typing import List, Tuple

import pandas as pd
from sklearn.model_selection import train_test_split

# Feature extraction helper
from features.dns_features import extract_features

# Model training helpers (renamed helper modules)
from models.train_rf_helper import train_random_forest
from models.train_xgb_helper import train_xgboost
from models.train_lr_helper import train_logistic_regression

# Model selection utility
from models.choose_best_model import choose_best_model

# Shared data loader
from data_loader import load_archive_datasets


def main() -> None:
    print("Loading datasets from archive folder...")
    df = load_archive_datasets()
    print(f"Total samples: {len(df)}")

    print("Extracting features...")
    X = extract_features(df)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    X_train_arr = X_train.values
    X_test_arr = X_test.values
    y_train_arr = y_train.values
    y_test_arr = y_test.values

    results: List[Tuple[object, float, str]] = []

    print("\nTraining RandomForest...")
    rf_model, rf_acc, rf_name = train_random_forest(X_train_arr, X_test_arr, y_train_arr, y_test_arr)
    results.append((rf_model, rf_acc, rf_name))
    print(f"{rf_name} accuracy: {rf_acc:.4f}")

    try:
        print("\nTraining XGBoost...")
        xgb_model, xgb_acc, xgb_name = train_xgboost(X_train_arr, X_test_arr, y_train_arr, y_test_arr)
        results.append((xgb_model, xgb_acc, xgb_name))
        print(f"{xgb_name} accuracy: {xgb_acc:.4f}")
    except RuntimeError as e:
        print(f"Skipping XGBoost: {e}")

    print("\nTraining Logistic Regression...")
    lr_model, lr_acc, lr_name = train_logistic_regression(X_train_arr, X_test_arr, y_train_arr, y_test_arr)
    results.append((lr_model, lr_acc, lr_name))
    print(f"{lr_name} accuracy: {lr_acc:.4f}")

    best_model, best_name = choose_best_model(results)
    print(f"\nBest Model Selected: {best_name}")


if __name__ == "__main__":
    main()
