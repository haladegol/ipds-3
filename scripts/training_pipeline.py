import os
import sys
import pandas as pd
import numpy as np
import joblib
import argparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models.ml.stage1_binary import Stage1BinaryClassifier
from models.ml.stage2_category import Stage2CategoryClassifiers, LABEL_TO_CATEGORY
from models.ml.stage2_multiclass import Stage2MulticlassFallback, ALL_SPECIFIC_ATTACKS
from models.ml.stage3_specific import Stage3SpecificClassifiers, LABEL_TO_SPECIFIC
from models.ml.pipeline import FLOW_FEATURES

DATA_PATH = r'c:\Users\asus\Downloads\hades2\uploads'
MODELS_DIR = "trained_models"

def load_dataset(sample_per_file=100000, max_total_rows=1000000):
    """Discover CSVs and load a combined sample safely."""
    csv_files = [f for f in os.listdir(DATA_PATH) if f.endswith('.csv') and ('2018' in f or 'cic' in f.lower())]
    print(f"Found {len(csv_files)} dataset files.")
    
    # Adjust for 'full' mode to stay within safe RAM limits (~8-10GB)
    if sample_per_file is None:
        sample_per_file = max_total_rows // len(csv_files) if csv_files else 100000
        print(f"Adjusting 'Full' mode to {sample_per_file} rows per file for system stability.")

    dfs = []
    for f in csv_files:
        path = os.path.join(DATA_PATH, f)
        print(f"Loading {sample_per_file} rows from {f}...")
        try:
            # Read only 1000 rows first to check columns
            temp_df = pd.read_csv(path, nrows=10, encoding='cp1252')
            temp_df.columns = temp_df.columns.str.strip().str.replace(' ', '_')
            
            # Use only features present in FLOW_FEATURES + Label
            cols_to_use = [c for c in temp_df.columns if c in FLOW_FEATURES]
            label_col_orig = next((c for c in temp_df.columns if c.lower() == 'label'), None)
            
            if not label_col_orig:
                print(f"Skipping {f}: No label column found.")
                continue
                
            # Map back to original names for read_csv
            orig_cols = [c.replace('_', ' ') for c in cols_to_use] # This is risky if strip removed spaces
            # Better: use usecols with a callable or just read all and filter
            df = pd.read_csv(path, nrows=sample_per_file, encoding='cp1252')
            dfs.append(df)
        except Exception as e:
            print(f"Error loading {f}: {e}")
            
    if not dfs:
        return None
        
    return pd.concat(dfs, ignore_index=True)

def preprocess_data(df):
    """Clean and prepare features/labels according to FLOW_FEATURES."""
    print(f"Preprocessing {len(df)} rows...")
    
    # Clean column names and remove duplicates caused by space→underscore normalization
    df.columns = df.columns.str.strip().str.replace(' ', '_')
    df = df.loc[:, ~df.columns.duplicated()]
    
    label_col = 'Label'
    if 'Label' not in df.columns:
        # Try finding case-insensitive label
        label_col = next((c for c in df.columns if c.lower() == 'label'), None)

    if not label_col:
        print(f"Warning: Label column not found. Available: {df.columns.tolist()}")
        return None, None
        
    y_raw = df[label_col]
    
    # Ensure all FLOW_FEATURES exist (fill with 0 if missing)
    for f in FLOW_FEATURES:
        if f not in df.columns:
            df[f] = 0
            
    # Select EXACTLY the features in the CORRECT order
    X = df[FLOW_FEATURES].copy()
    
    # Clean numeric data
    X = X.apply(pd.to_numeric, errors='coerce')
    X = X.fillna(0)
    X = X.replace([np.inf, -np.inf], 0)
    
    return X, y_raw

def main():
    parser = argparse.ArgumentParser(description="HADES Training Pipeline")
    parser.add_argument("--full", action="store_true", help="Train on full dataset (might use a lot of RAM)")
    parser.add_argument("--sample", type=int, default=100000, help="Sample count per file")
    args = parser.parse_args()

    sample_val = None if args.full else args.sample
    print(f"Starting Training Process (MODE: {'FULL' if args.full else 'SAMPLED'})")

    df = load_dataset(sample_per_file=sample_val)
    if df is None:
        print("No data loaded. Exiting.")
        return

    X, y_raw = preprocess_data(df)
    if X is None:
        return

    print(f"Dataset finalized: {X.shape}")
    
    # --- STAGE 1: Binary ---
    print("\n--- Training Stage 1 (Binary) ---")
    y_binary = (y_raw != 'Benign').astype(int)
    s1 = Stage1BinaryClassifier(MODELS_DIR)
    s1.train(X, y_binary)
    print("Stage 1 Trained and Saved.")

    # --- STAGE 2.1: Category Classifiers ---
    print("\n--- Training Stage 2.1 (Categories) ---")
    anomaly_mask = y_binary == 1
    if anomaly_mask.any():
        X_anom = X[anomaly_mask]
        y_anom_raw = y_raw[anomaly_mask]
        
        s2 = Stage2CategoryClassifiers(MODELS_DIR)
        for cat in s2.is_trained.keys():
            print(f"Training Category: {cat}")
            y_cat = y_anom_raw.apply(lambda x: 1 if LABEL_TO_CATEGORY.get(x) == cat else 0)
            if y_cat.sum() > 0:
                s2.train(cat, X_anom, y_cat)
            else:
                print(f"Skipping {cat}: No samples found.")
        print("Stage 2.1 Trained and Saved.")
    else:
        print("No anomalies found for Stage 2 training.")

    # --- STAGE 2.2: Multiclass fallback ---
    print("\n--- Training Stage 2.2 (Multiclass) ---")
    if anomaly_mask.any():
        s2m = Stage2MulticlassFallback(MODELS_DIR)
        atk_to_id = {atk: i for i, atk in enumerate(ALL_SPECIFIC_ATTACKS)}
        y_atk_ids = y_anom_raw.apply(lambda x: atk_to_id.get(LABEL_TO_SPECIFIC.get(x), -1))
        
        valid_mask = y_atk_ids != -1
        if valid_mask.any():
            s2m.train(X_anom[valid_mask], y_atk_ids[valid_mask])
            print("Stage 2.2 Trained and Saved.")

    # --- STAGE 3: Specific Attacks ---
    print("\n--- Training Stage 3 (Specific) ---")
    if anomaly_mask.any():
        s3 = Stage3SpecificClassifiers(MODELS_DIR)
        for cat, attacks in s3.label_maps.items():
            print(f"Training Specific Attacks for: {cat}")
            cat_mask = y_anom_raw.apply(lambda x: LABEL_TO_CATEGORY.get(x) == cat)
            if cat_mask.any():
                X_cat = X_anom[cat_mask]
                y_cat_raw = y_anom_raw[cat_mask]
                
                atk_to_id = {atk: i for i, atk in s3.label_maps[cat].items()}
                y_atk_ids = y_cat_raw.apply(lambda x: atk_to_id.get(LABEL_TO_SPECIFIC.get(x), -1))
                
                valid_mask = y_atk_ids != -1
                if valid_mask.any():
                    s3.train(cat, X_cat[valid_mask], y_atk_ids[valid_mask])
        print("Stage 3 Trained and Saved.")

    print("\nTraining complete!")

if __name__ == "__main__":
    main()
