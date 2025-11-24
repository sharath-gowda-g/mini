"""Logistic Regression training helper.

Provides `train_logistic_regression` which fits a simple
LogisticRegression model and returns the fitted model, test accuracy,
and the model name.
"""
from typing import Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score


def train_logistic_regression(X_train: np.ndarray, X_test: np.ndarray, y_train: np.ndarray, y_test: np.ndarray) -> Tuple[LogisticRegression, float, str]:
    """Train a LogisticRegression and evaluate on the test set.

    Uses solver='liblinear' for simplicity and compatibility.

    Returns (model, accuracy, "LogisticRegression").
    """
    model = LogisticRegression(solver="liblinear", class_weight="balanced", max_iter=1000)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    return model, acc, "LogisticRegression"
