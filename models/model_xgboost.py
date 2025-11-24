"""XGBoost training helper.

Provides `train_xgboost` which trains an XGBClassifier with sensible
hyperparameters for tabular DNS features and returns the fitted model,
test accuracy, and the model name.
"""
from typing import Tuple

import numpy as np
from sklearn.metrics import accuracy_score


def train_xgboost(X_train: np.ndarray, X_test: np.ndarray, y_train: np.ndarray, y_test: np.ndarray) -> Tuple[object, float, str]:
    """Train an XGBoost classifier and evaluate on the test set.

    Hyperparameters:
      - n_estimators=400
      - max_depth=12
      - learning_rate=0.05

    Raises a RuntimeError if `xgboost` is not installed.

    Returns (trained_model, accuracy, "XGBoost").
    """
    try:
        from xgboost import XGBClassifier
    except Exception as e:
        raise RuntimeError("xgboost is not installed. Install with: pip install xgboost") from e

    model = XGBClassifier(
        n_estimators=400,
        max_depth=12,
        learning_rate=0.05,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    return model, acc, "XGBoost"
