"""Utilities to select and persist the best trained model.

Provides `choose_best_model` which accepts a list of `(model, accuracy, name)`
tuples, prints a small comparison table, saves the best model to
`best_dns_model.pkl`, and returns `(best_model, best_name)`.
"""
from typing import List, Tuple
import joblib


def choose_best_model(models_list: List[Tuple[object, float, str]]) -> Tuple[object, str]:
    """Select the model with highest accuracy from `models_list`.

    Parameters
    - models_list: list of tuples (model_obj, accuracy, model_name)

    Returns
    - (best_model_obj, best_model_name)

    Side-effects
    - Prints a simple comparison table to stdout.
    - Saves the best model to `best_dns_model.pkl` using joblib.
    """
    if not models_list:
        raise ValueError("models_list must contain at least one model tuple")

    # Print header
    print("\nModel comparison:")
    print(f"{'Model':<20} {'Accuracy':>10}")
    print("-" * 32)

    best_idx = 0
    best_acc = float(models_list[0][1])
    for i, (_, acc, name) in enumerate(models_list):
        print(f"{name:<20} {acc:10.4f}")
        if float(acc) > best_acc:
            best_acc = float(acc)
            best_idx = i

    best_model, best_accuracy, best_name = models_list[best_idx]

    # Save best model along with its name so downstream code can report which
    # model was used for predictions.
    payload = {"model": best_model, "name": best_name}
    joblib.dump(payload, "best_dns_model.pkl")
    print(f"\n✅ Best model: {best_name} (accuracy={best_accuracy:.4f}) saved to best_dns_model.pkl")

    return best_model, best_name
