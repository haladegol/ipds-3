"""
HADES Final 2 — Model Training Script
Train all ML models on the CIC-IDS 2018 dataset.

Usage:
    python -m models.ml.train_models --data_dir /path/to/cic-ids-2018-csvs/

Expected CSV files in data_dir (from CIC-IDS 2018):
    - Friday-02-03-2018_TrafficForIdentification.csv
    - Thursday-01-03-2018_TrafficForIdentification.csv
    - ... (all day CSVs)

Or a single combined CSV file:
    python -m models.ml.train_models --data_file combined_dataset.csv
"""
import os
import sys
import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from models.ml.stage1_binary import Stage1BinaryClassifier
from models.ml.stage2_category import Stage2CategoryClassifiers, LABEL_TO_CATEGORY, ATTACK_CATEGORIES
from models.ml.stage2_multiclass import Stage2MulticlassFallback
from models.ml.stage3_specific import Stage3SpecificClassifiers, LABEL_TO_SPECIFIC, CATEGORY_SPECIFIC_ATTACKS
from models.ml.pipeline import FLOW_FEATURES


def load_data(data_dir=None, data_file=None):
    """Load CIC-IDS 2018 data from directory of CSVs or single file."""
    if data_file and os.path.exists(data_file):
        print(f"[*] Loading single file: {data_file}")
        df = pd.read_csv(data_file, low_memory=False)
    elif data_dir and os.path.isdir(data_dir):
        print(f"[*] Loading all CSVs from: {data_dir}")
        csv_files = [f for f in os.listdir(data_dir) if f.endswith(".csv")]
        dfs = []
        for f in csv_files:
            print(f"    Loading {f}...")
            dfs.append(pd.read_csv(os.path.join(data_dir, f), low_memory=False))
        df = pd.concat(dfs, ignore_index=True)
    else:
        print("[!] No data found. Please provide --data_dir or --data_file.")
        sys.exit(1)

    # Clean column names
    df.columns = df.columns.str.strip()
    print(f"[*] Loaded {len(df)} rows, {len(df.columns)} columns")
    return df


def prepare_features(df):
    """Extract feature matrix and handle missing/infinite values."""
    available = [f for f in FLOW_FEATURES if f in df.columns]
    print(f"[*] Using {len(available)} of {len(FLOW_FEATURES)} expected features")

    X = df[available].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Try to find the label column
    label_col = None
    for candidate in ["Label", "label", "Attack", "attack", "class", "Class"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        print("[!] Cannot find label column. Available columns:")
        print(df.columns.tolist())
        sys.exit(1)

    y_raw = df[label_col].str.strip()
    print(f"[*] Label column: '{label_col}' with {y_raw.nunique()} unique values")
    print(f"    Distribution:\n{y_raw.value_counts()}\n")

    return X, y_raw


def train_stage1(X, y_raw, models_dir):
    """Train Stage 1: Binary Normal vs Anomaly."""
    print("\n" + "=" * 60)
    print("STAGE 1: Binary Classifier (Normal vs Anomaly)")
    print("=" * 60)

    # Map labels: Benign/Normal → 0, everything else → 1
    y = y_raw.apply(lambda x: 0 if x.lower() in ["benign", "normal"] else 1).values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    classifier = Stage1BinaryClassifier(models_dir)
    classifier.train(X_train, y_train)

    y_pred = classifier.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[✓] Stage 1 Accuracy: {acc:.4f} ({acc * 100:.2f}%)")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Anomaly"]))
    return classifier


def train_stage2_1(X, y_raw, models_dir):
    """Train Stage 2.1: Five binary category classifiers."""
    print("\n" + "=" * 60)
    print("STAGE 2.1: Category Binary Classifiers")
    print("=" * 60)

    # Only use anomaly samples
    is_anomaly = y_raw.apply(lambda x: x.lower() not in ["benign", "normal"])
    X_anomaly = X[is_anomaly].copy()
    y_anomaly = y_raw[is_anomaly].copy()

    # Map to categories
    y_categories = y_anomaly.map(LABEL_TO_CATEGORY)
    unmapped = y_categories.isna()
    if unmapped.any():
        print(f"[!] {unmapped.sum()} samples have unmapped labels:")
        print(y_anomaly[unmapped].value_counts())
        X_anomaly = X_anomaly[~unmapped]
        y_categories = y_categories[~unmapped]

    classifiers = Stage2CategoryClassifiers(models_dir)

    for cat in ATTACK_CATEGORIES:
        print(f"\n--- Training classifier for: {cat} ---")
        y_binary = (y_categories == cat).astype(int).values
        pos_count = y_binary.sum()
        neg_count = len(y_binary) - pos_count
        print(f"    Positive: {pos_count}, Negative: {neg_count}")

        if pos_count < 5:
            print(f"    [!] Too few positive samples, skipping {cat}")
            continue

        X_train, X_test, y_train, y_test = train_test_split(
            X_anomaly, y_binary, test_size=0.2, random_state=42, stratify=y_binary
        )
        classifiers.train(cat, X_train, y_train)

        y_pred = classifiers.classifiers[cat].predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"    [✓] {cat} Accuracy: {acc:.4f} ({acc * 100:.2f}%)")
        print(classification_report(y_test, y_pred, target_names=[f"Not {cat}", cat]))

    return classifiers


def train_stage2_2(X, y_raw, models_dir):
    """Train Stage 2.2: Multiclass fallback classifier."""
    print("\n" + "=" * 60)
    print("STAGE 2.2: Multiclass Fallback Classifier")
    print("=" * 60)

    is_anomaly = y_raw.apply(lambda x: x.lower() not in ["benign", "normal"])
    X_anomaly = X[is_anomaly].copy()
    y_anomaly = y_raw[is_anomaly].copy()

    y_categories = y_anomaly.map(LABEL_TO_CATEGORY)
    valid = ~y_categories.isna()
    X_anomaly = X_anomaly[valid]
    y_categories = y_categories[valid]

    le = LabelEncoder()
    le.classes_ = np.array(ATTACK_CATEGORIES)
    y_encoded = np.array([ATTACK_CATEGORIES.index(c) for c in y_categories])

    X_train, X_test, y_train, y_test = train_test_split(
        X_anomaly, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    classifier = Stage2MulticlassFallback(models_dir)
    classifier.train(X_train, y_train)

    y_pred = classifier.model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[✓] Stage 2.2 Accuracy: {acc:.4f} ({acc * 100:.2f}%)")
    print(classification_report(y_test, y_pred, target_names=ATTACK_CATEGORIES))
    return classifier


def train_stage3(X, y_raw, models_dir):
    """Train Stage 3: Per-category specific attack classifiers."""
    print("\n" + "=" * 60)
    print("STAGE 3: Specific Attack Classifiers")
    print("=" * 60)

    is_anomaly = y_raw.apply(lambda x: x.lower() not in ["benign", "normal"])
    X_anomaly = X[is_anomaly].copy()
    y_anomaly = y_raw[is_anomaly].copy()

    y_specific = y_anomaly.map(LABEL_TO_SPECIFIC)
    y_category = y_anomaly.map(LABEL_TO_CATEGORY)

    classifiers = Stage3SpecificClassifiers(models_dir)

    for cat, attacks in CATEGORY_SPECIFIC_ATTACKS.items():
        print(f"\n--- Training specific classifier for: {cat} ---")
        mask = y_category == cat
        X_cat = X_anomaly[mask].copy()
        y_cat = y_specific[mask].copy()

        valid = ~y_cat.isna()
        X_cat = X_cat[valid]
        y_cat = y_cat[valid]

        if len(X_cat) < 10:
            print(f"    [!] Too few samples ({len(X_cat)}), skipping {cat}")
            continue

        le = LabelEncoder()
        le.fit(attacks)
        y_encoded = le.transform(y_cat)

        print(f"    Samples: {len(X_cat)}, Classes: {y_cat.nunique()}")
        print(f"    Distribution: {y_cat.value_counts().to_dict()}")

        X_train, X_test, y_train, y_test = train_test_split(
            X_cat, y_encoded, test_size=0.2, random_state=42,
            stratify=y_encoded if y_cat.nunique() > 1 else None
        )

        classifiers.train(cat, X_train, y_train)

        y_pred = classifiers.classifiers[cat].predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"    [✓] {cat} Specific Accuracy: {acc:.4f} ({acc * 100:.2f}%)")

        # Get labels present in test set
        present_labels = sorted(set(y_test) | set(y_pred))
        present_names = [attacks[i] for i in present_labels if i < len(attacks)]
        print(classification_report(y_test, y_pred, labels=present_labels, target_names=present_names))

    return classifiers


def main():
    parser = argparse.ArgumentParser(description="HADES Final 2 - Train all ML models")
    parser.add_argument("--data_dir", type=str, help="Directory containing CIC-IDS 2018 CSV files")
    parser.add_argument("--data_file", type=str, help="Path to a single combined CSV file")
    parser.add_argument("--models_dir", type=str, default="trained_models", help="Directory to save models")
    args = parser.parse_args()

    if not args.data_dir and not args.data_file:
        print("[!] Please provide --data_dir or --data_file")
        print("    Example: python -m models.ml.train_models --data_file dataset.csv")
        sys.exit(1)

    os.makedirs(args.models_dir, exist_ok=True)

    # Load and prepare data
    df = load_data(data_dir=args.data_dir, data_file=args.data_file)
    X, y_raw = prepare_features(df)

    # Train all stages
    train_stage1(X, y_raw, args.models_dir)
    train_stage2_1(X, y_raw, args.models_dir)
    train_stage2_2(X, y_raw, args.models_dir)
    train_stage3(X, y_raw, args.models_dir)

    print("\n" + "=" * 60)
    print("[✓] ALL MODELS TRAINED SUCCESSFULLY!")
    print(f"    Models saved to: {os.path.abspath(args.models_dir)}/")
    print("=" * 60)


if __name__ == "__main__":
    main()
