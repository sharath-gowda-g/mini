"""Prediction script — renamed from `predict_dns.py`.

Loads `best_dns_model.pkl` and classifies domains in `dns_log.csv`.
"""

# Original content from predict_dns.py; filename updated.
import pandas as pd
import numpy as np
import math
import joblib
from termcolor import colored  # for colored console output
import re
import io
from pandas.errors import ParserError

# -------------------------
# File paths
# -------------------------
MODEL_PATH = "best_dns_model.pkl"      # Trained model file
INPUT_CSV = "dns_log.csv"         # DNS logs captured in real-time
OUTPUT_CSV = "dns_predictions.csv"  # CSV file to save predictions

# Import feature helpers from dns_features
from features.dns_features import (
    calc_entropy,
    split_labels,
    entropy_of_labels,
    repeated_char_run_max,
    char_ratios,
    get_tld,
    has_base64_label,
    has_tunneling_keyword,
    digit_fraction_of_longest_label,
    extract_features,
    uncommon_tlds,
)

# -------------------------
# Load trained model and DNS log data
# -------------------------
loaded = joblib.load(MODEL_PATH)

# Support both old-style model files (model object) and the new format
# where we save a dict {"model": model_obj, "name": model_name}.
if isinstance(loaded, dict) and "model" in loaded:
    model = loaded["model"]
    model_name = loaded.get("name", "unknown")
else:
    model = loaded
    # Fallback name for legacy model files
    try:
        model_name = type(model).__name__
    except Exception:
        model_name = "unknown"

print(f"🔍 Using Model: {model_name}")

def read_dns_csv(path):
    try:
        return pd.read_csv(path)
    except ParserError:
        cleaned_lines = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                ln = line.rstrip('\n').rstrip('\r')
                while ln.endswith(','):
                    ln = ln[:-1]
                cleaned_lines.append(ln + '\n')
        buf = io.StringIO(''.join(cleaned_lines))
        return pd.read_csv(buf)

df = read_dns_csv(INPUT_CSV)      # Load captured DNS queries
if "qname" not in df.columns:
    raise ValueError("❌ 'qname' column not found in dns_log.csv")  # Safety check

df.dropna(subset=["qname"], inplace=True)  # Remove rows with empty domain names

# Use shared feature extractor from dns_features.py
X = extract_features(df)  # Extract features for prediction

# -------------------------
# Predict probability of suspicious domain
# -------------------------
probs = model.predict_proba(X)[:, 1]  # Probability of being suspicious

# Threshold to classify domains
threshold = 0.7  # Conservative: higher threshold reduces false positives

# -------------------------
# Whitelist of known safe domains
# -------------------------
legitimate_domains = {
    'google.com', 'google.co.in', 'googleapis.com', 'gstatic.com', 'gvt2.com',
    'facebook.com', 'fbcdn.net', 'doubleclick.net', 'googlesyndication.com',
    'youtube.com', 'leetcode.com', 'takeuforward.org', 'perplexity.ai',
    'anthropic.com', 'stripe.com', 'intercom.io', 'cloudflare.com',
    'cursor.sh', 'codeium.com', 'razorpay.com', 'msn.com', 'microsoft.com',
    'linkedin.com', 'signalhire.com', 'vimeo.com', 'sentry.io', 'datadoghq.com','claude.ai'
}

def is_legitimate_domain(qname):
    """Check if a domain is in whitelist or matches common patterns"""
    qname = str(qname).lower().strip('.')
    
    if qname in legitimate_domains:
        return True
    
    for domain in legitimate_domains:
        if qname.endswith('.' + domain):
            return True
    
    # Check common safe prefixes
    legitimate_patterns = [
        'www.', 'api.', 'cdn.', 'static.', 'assets.', 'fonts.',
        'ssl.', 'secure.', 'mail.', 'ftp.', 'blog.', 'shop.',
        'news.', 'support.', 'help.', 'docs.', 'status.'
    ]
    
    for pattern in legitimate_patterns:
        if qname.startswith(pattern):
            return True
    
    return False

# -------------------------
# Assign labels based on probability and rules
# -------------------------
def label_row(qname, p, feat_row):
    q = str(qname)
    labels = split_labels(q)
    tld_uncommon = get_tld(q) in uncommon_tlds
    base64_present = has_base64_label(labels)
    tunneling_present = has_tunneling_keyword(labels)
    longest_label_digit_frac = digit_fraction_of_longest_label(labels)
    many_labels = len(labels) >= 5

    if is_legitimate_domain(qname):
        if base64_present or (tunneling_present and (feat_row["entropy_full"] >= 3.8 or many_labels)):
            return "Suspicious"
        return "Suspicious" if p >= 0.95 else "Safe"

    if base64_present:
        return "Suspicious"

    if tunneling_present and (feat_row["entropy_full"] >= 3.6 or feat_row["num_labels"] >= 3):
        return "Suspicious"

    if tld_uncommon and (
        feat_row["entropy_full"] >= 3.8 or longest_label_digit_frac >= 0.3 or feat_row["total_len"] >= 60
    ):
        return "Suspicious"

    if many_labels and feat_row["entropy_label_max"] >= 4.0:
        return "Suspicious"

    if p >= threshold:
        return "Suspicious"
    if tld_uncommon and p >= 0.5:
        return "Suspicious"
    return "Safe"

pred_labels = [
    label_row(q, p, X.iloc[i])
    for i, (q, p) in enumerate(zip(df["qname"], probs))
]

df["prediction"] = pred_labels
df["confidence"] = (probs * 100).round(2)

# -------------------------
# Print results in color
# -------------------------
print("\n🔍 DNS Prediction Results:\n")
for qname, label, conf in zip(df["qname"], df["prediction"], df["confidence"]):
    suffix = f" [Predicted using {model_name}]"
    if label == "Suspicious":
        print(colored(f"[SUSPICIOUS] {qname}  →  {conf}% confidence" + suffix, "red"))
    else:
        print(colored(f"[SAFE] {qname}  →  {conf}% confidence" + suffix, "green"))

# -------------------------
# Save predictions to CSV
# -------------------------
color_map = df["prediction"].map({
    "Safe": "🟢 Safe",
    "Suspicious": "🔴 Suspicious"
})
df_out = pd.DataFrame({
    "qname": df["qname"],
    "prediction": color_map,
    "confidence": df["confidence"]
})
df_out.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")

print(f"\n✅ Predictions saved to {OUTPUT_CSV}")
