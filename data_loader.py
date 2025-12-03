"""Shared utility for loading DNS dataset from archive folder."""
from pathlib import Path
from typing import Optional
import pandas as pd

# Archive paths
ARCHIVE_BENIGN_PATH = "archive/dns-exfiltration-dataset/02_generated_dataset/benign/benign.csv"
ARCHIVE_MALICIOUS_DIR = "archive/dns-exfiltration-dataset/02_generated_dataset/malicious"
WHITELIST_PATH = "whitelist_domains.csv"  # Custom whitelist of known safe domains


def load_archive_datasets(limit_samples: Optional[int] = None) -> pd.DataFrame:
    """Load all CSV files from the archive folder and combine them.
    
    Args:
        limit_samples: Optional limit on number of samples per class (for faster testing)
    
    Returns:
        Combined DataFrame with 'qname' and 'label' columns
    """
    print("Loading datasets from archive folder...")
    
    # Load benign data
    print(f"Loading benign data from {ARCHIVE_BENIGN_PATH}...")
    benign_df = pd.read_csv(ARCHIVE_BENIGN_PATH)
    
    # Map dns_domain_name to qname and label to binary
    if "dns_domain_name" in benign_df.columns:
        benign_df["qname"] = benign_df["dns_domain_name"]
    else:
        raise RuntimeError("Benign CSV must contain 'dns_domain_name' column")
    
    # Map label: "Benign" -> 0
    if "label" in benign_df.columns:
        benign_df = benign_df[benign_df["label"].str.lower() == "benign"].copy()
        benign_df["label"] = 0
    else:
        benign_df["label"] = 0
    
    # Load custom whitelist domains if it exists
    whitelist_path = Path(WHITELIST_PATH)
    if whitelist_path.exists():
        print(f"\nLoading custom whitelist from {WHITELIST_PATH}...")
        try:
            whitelist_df = pd.read_csv(WHITELIST_PATH)
            if "dns_domain_name" in whitelist_df.columns:
                whitelist_df["qname"] = whitelist_df["dns_domain_name"]
                whitelist_df["label"] = 0  # All whitelist domains are benign
                # Remove duplicates that might already be in benign_df
                whitelist_df = whitelist_df[~whitelist_df["qname"].isin(benign_df["qname"])]
                if len(whitelist_df) > 0:
                    print(f"  Adding {len(whitelist_df)} whitelist domains to benign dataset")
                    benign_df = pd.concat([benign_df, whitelist_df[["qname", "label"]]], ignore_index=True)
                else:
                    print("  All whitelist domains already in benign dataset")
            else:
                print(f"  Warning: {WHITELIST_PATH} missing 'dns_domain_name' column, skipping")
        except Exception as e:
            print(f"  Warning: Could not load whitelist: {e}")
    else:
        print(f"\nNo custom whitelist found at {WHITELIST_PATH} (this is optional)")
    
    # Limit samples if specified
    if limit_samples and len(benign_df) > limit_samples:
        benign_df = benign_df.sample(n=limit_samples, random_state=42).reset_index(drop=True)
    
    print(f"  Loaded {len(benign_df)} benign samples")
    
    # Load all malicious datasets
    malicious_dfs = []
    malicious_dir = Path(ARCHIVE_MALICIOUS_DIR)
    
    if not malicious_dir.exists():
        raise RuntimeError(f"Malicious directory not found: {ARCHIVE_MALICIOUS_DIR}")
    
    # Find all CSV files in malicious subdirectories
    csv_files = list(malicious_dir.rglob("*.csv"))
    print(f"\nFound {len(csv_files)} malicious CSV files:")
    
    for csv_file in csv_files:
        print(f"  Loading {csv_file.name}...")
        df = pd.read_csv(csv_file)
        
        # Map dns_domain_name to qname
        if "dns_domain_name" in df.columns:
            df["qname"] = df["dns_domain_name"]
        else:
            print(f"    Warning: {csv_file.name} missing 'dns_domain_name' column, skipping")
            continue
        
        # Map label: "Malicious" -> 1
        if "label" in df.columns:
            df = df[df["label"].str.lower() == "malicious"].copy()
            df["label"] = 1
        else:
            df["label"] = 1
        
        malicious_dfs.append(df)
        print(f"    Loaded {len(df)} samples")
    
    if not malicious_dfs:
        raise RuntimeError("No malicious datasets loaded. Check archive structure.")
    
    # Combine all malicious data
    malicious_df = pd.concat(malicious_dfs, ignore_index=True)
    
    # Limit samples if specified
    if limit_samples and len(malicious_df) > limit_samples:
        malicious_df = malicious_df.sample(n=limit_samples, random_state=42).reset_index(drop=True)
    
    print(f"\nTotal malicious samples: {len(malicious_df)}")
    
    # Combine benign and malicious
    df = pd.concat([benign_df, malicious_df], ignore_index=True)
    
    # Keep only necessary columns and ensure qname is clean
    df = df[["qname", "label"]].copy()
    df["qname"] = df["qname"].fillna("").astype(str)
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\nTotal dataset size: {len(df)}")
    print(f"  Benign (0): {len(df[df['label'] == 0])}")
    print(f"  Malicious (1): {len(df[df['label'] == 1])}")
    
    return df


