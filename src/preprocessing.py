"""
Data Preprocessing Module for Phishing URL Detection.

Handles raw dataset loading, cleaning, feature matrix extraction, and dataset splitting
without data leakage.
"""

import os
import sys
import pandas as pd
from sklearn.model_selection import train_test_split

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.feature_extraction import extract_features
except ImportError:
    from feature_extraction import extract_features


def load_raw_data(file_path: str = 'data/raw/phishing_dataset.csv') -> pd.DataFrame:
    """
    Loads raw CSV dataset and performs initial data hygiene (handling missing values and duplicates).
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Raw dataset file not found at '{file_path}'. Please run src/generate_dataset.py first.")
    
    df = pd.read_csv(file_path)
    initial_count = len(df)
    
    # Drop rows with missing URL or label
    df = df.dropna(subset=['url', 'label'])
    
    # Drop duplicate URLs to prevent data leakage between train and test sets
    df = df.drop_duplicates(subset=['url'])
    
    # Ensure labels are integers
    df['label'] = df['label'].astype(int)
    
    print(f"[Preprocessing] Loaded {len(df)} valid records (removed {initial_count - len(df)} duplicates/nulls).")
    return df


def extract_features_from_dataframe(df: pd.DataFrame) -> tuple:
    """
    Extracts lexical features for all URLs in the dataframe.
    
    Returns:
        X (pd.DataFrame): Feature matrix
        y (pd.Series): Target labels (0 = safe, 1 = phishing)
    """
    print(f"[Preprocessing] Extracting URL features for {len(df)} entries...")
    feature_list = []
    
    for url in df['url']:
        feats = extract_features(url)
        feature_list.append(feats)
        
    X = pd.DataFrame(feature_list)
    y = df['label'].reset_index(drop=True)
    
    return X, y


def preprocess_pipeline(raw_path: str = 'data/raw/phishing_dataset.csv', test_size: float = 0.2, random_state: int = 42):
    """
    Complete data preprocessing pipeline: load -> clean -> extract features -> train/test split.
    
    Returns:
        X_train, X_test, y_train, y_test, feature_names
    """
    df = load_raw_data(raw_path)
    X, y = extract_features_from_dataframe(df)
    
    # Perform stratified split to maintain class balance in train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    feature_names = list(X.columns)
    print(f"[Preprocessing] Split complete: {len(X_train)} training samples, {len(X_test)} test samples.")
    print(f"[Preprocessing] Extracted {len(feature_names)} features per URL.")
    
    return X_train, X_test, y_train, y_test, feature_names


if __name__ == '__main__':
    X_train, X_test, y_train, y_test, features = preprocess_pipeline()
