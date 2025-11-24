"""Random Forest training helper.

Provides a single function `train_random_forest` that trains a
sklearn RandomForestClassifier with the same hyperparameters used in
`train_model.py` and returns the fitted model, accuracy on the test set,
and the model name string.
"""
from typing import Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score


def train_random_forest(X_train: np.ndarray, X_test: np.ndarray, y_train: np.ndarray, y_test: np.ndarray) -> Tuple[RandomForestClassifier, float, str]:
    """Train a RandomForestClassifier and evaluate on the test set.

    Parameters
    - X_train, X_test: feature matrices
    - y_train, y_test: label vectors

    Returns a tuple: (trained_model, accuracy_score, "RandomForest").
    """
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
    acc = float(accuracy_score(y_test, y_pred))

    return model, acc, "RandomForest"
