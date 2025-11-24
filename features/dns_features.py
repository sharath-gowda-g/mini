"""Feature extraction utilities for DNS tunneling detection.

This module centralises all feature helper functions used by the
training and prediction scripts so they can be imported from
``features.dns_features``. The logic is unchanged from the original
project — only packaged with type hints, docstrings and safe handling
for empty input values.
"""
from __future__ import annotations

import math
import re
from typing import List, Tuple

import numpy as np
import pandas as pd

# Reuse the same lists of uncommon TLDs and tunneling keywords
uncommon_tlds = {"xyz", "top", "biz", "tk", "gq", "cf", "ga", "ml", "space", "info", "click"}
tunneling_keywords = {"tunnel", "dns", "xfil", "exfil", "data", "payload", "c2", "leak", "dnscat", "iodine"}


def calc_entropy(s: object) -> float:
    """Return Shannon entropy of string representation of ``s``.

    Safe for empty or non-string inputs: converts to string and returns
    0.0 for empty values.
    """
    s = str(s)
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def split_labels(qname: object) -> List[str]:
    """Split a domain name into labels.

    Example: 'www.google.com' -> ['www', 'google', 'com']
    Safe for empty inputs.
    """
    q = str(qname).strip('.')
    return [lbl for lbl in q.split('.') if lbl]


def entropy_of_labels(labels: List[str]) -> Tuple[float, float]:
    """Return (mean_entropy, max_entropy) across provided labels.

    If labels is empty returns (0.0, 0.0).
    """
    if not labels:
        return 0.0, 0.0
    ents = [calc_entropy(l) for l in labels]
    return float(np.mean(ents)), float(np.max(ents))


def repeated_char_run_max(s: object) -> int:
    """Return the longest run of repeated characters in the string.

    Example: 'aaabb' -> 3
    """
    s = str(s)
    if not s:
        return 0
    max_run = 1
    run = 1
    last = s[0]
    for ch in s[1:]:
        if ch == last:
            run += 1
            if run > max_run:
                max_run = run
        else:
            run = 1
            last = ch
    return max_run


def char_ratios(s: object) -> Tuple[float, float, float, float]:
    """Return ratios (digits, vowels, consonants, non_alnum) for the string.

    Safe for empty inputs: returns four zeros.
    """
    s = str(s)
    if not s:
        return 0.0, 0.0, 0.0, 0.0
    letters = sum(c.isalpha() for c in s)
    digits = sum(c.isdigit() for c in s)
    vowels = sum(c.lower() in 'aeiou' for c in s)
    non_alnum = sum(not c.isalnum() for c in s)
    n = len(s)
    consonants = max(0, letters - vowels)
    return digits / n, vowels / n, consonants / n, non_alnum / n


def get_tld(qname: object) -> str:
    """Return the last label (TLD) of the provided domain name in lower-case.

    Safe for empty inputs: returns an empty string.
    """
    q = str(qname).strip('.')
    parts = [p for p in q.split('.') if p]
    return parts[-1].lower() if parts else ""


def has_base64_label(labels: List[str]) -> bool:
    """Return True if any label looks like a base64-style long token.

    Uses the same heuristic as the original project: label length >= 16
    and matching base64 character set while not matching simple lowercase
    DNS label pattern.
    """
    for lbl in labels:
        if len(lbl) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", lbl) and not re.fullmatch(r"[a-z0-9-]+", lbl):
            return True
    return False


def has_tunneling_keyword(labels: List[str]) -> bool:
    """Return True if any tunneling-related keyword is present in labels."""
    low = ".".join(labels).lower()
    return any(k in low for k in tunneling_keywords)


def digit_fraction_of_longest_label(labels: List[str]) -> float:
    """Return the fraction of digits in the longest label (0.0 if not available)."""
    if not labels:
        return 0.0
    longest = max(labels, key=len)
    if not longest:
        return 0.0
    digits = sum(ch.isdigit() for ch in longest)
    return digits / len(longest)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract the numeric feature DataFrame from input DataFrame containing `qname`.

    This function returns a DataFrame with the same columns and names used by
    `train_model.py` and `predict_dns.py` so the result can be fed directly to
    scikit-learn models or the prediction logic in the project.

    Parameters
    - df: pandas DataFrame with at least a `qname` column (values may be empty).

    Returns
    - pandas DataFrame with numeric features.
    """
    total_len = []
    num_labels = []
    max_label_len = []
    mean_label_len = []
    std_label_len = []
    entropy_full = []
    entropy_label_mean = []
    entropy_label_max = []
    digit_ratio = []
    vowel_ratio = []
    consonant_ratio = []
    non_alnum_ratio = []
    repeat_run_max = []
    tld_uncommon_col = []
    base64_label_present_col = []
    tunneling_keyword_present_col = []
    longest_label_digit_frac_col = []

    for q in df.get("qname", []):
        q = str(q)
        labels = split_labels(q)

        lens = [len(l) for l in labels] if labels else [0]
        total_len.append(len(q))
        num_labels.append(len(labels))
        max_label_len.append(int(np.max(lens)))
        mean_label_len.append(float(np.mean(lens)))
        std_label_len.append(float(np.std(lens)))

        entropy_full.append(calc_entropy(q))
        m_ent, x_ent = entropy_of_labels(labels)
        entropy_label_mean.append(m_ent)
        entropy_label_max.append(x_ent)

        d_r, v_r, c_r, n_r = char_ratios(q)
        digit_ratio.append(d_r)
        vowel_ratio.append(v_r)
        consonant_ratio.append(c_r)
        non_alnum_ratio.append(n_r)

        repeat_run_max.append(repeated_char_run_max(q))

        tld_uncommon_col.append(1 if get_tld(q) in uncommon_tlds else 0)
        base64_label_present_col.append(1 if has_base64_label(labels) else 0)
        tunneling_keyword_present_col.append(1 if has_tunneling_keyword(labels) else 0)
        longest_label_digit_frac_col.append(float(digit_fraction_of_longest_label(labels)))

    features = pd.DataFrame({
        "total_len": total_len,
        "num_labels": num_labels,
        "max_label_len": max_label_len,
        "mean_label_len": mean_label_len,
        "std_label_len": std_label_len,
        "entropy_full": entropy_full,
        "entropy_label_mean": entropy_label_mean,
        "entropy_label_max": entropy_label_max,
        "digit_ratio": digit_ratio,
        "vowel_ratio": vowel_ratio,
        "consonant_ratio": consonant_ratio,
        "non_alnum_ratio": non_alnum_ratio,
        "repeat_run_max": repeat_run_max,
        "tld_uncommon": tld_uncommon_col,
        "base64_label_present": base64_label_present_col,
        "tunneling_keyword_present": tunneling_keyword_present_col,
        "longest_label_digit_frac": longest_label_digit_frac_col,
    })
    return features
