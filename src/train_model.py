"""
Model Training & Comparison Pipeline for Phishing URL Detection.

Trains Logistic Regression, Decision Tree, and Random Forest models,
compares metrics, selects the best model, and saves artifacts to models/ directory.
"""

import os
import sys
import json
import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.generate_dataset import create_dataset
    from src.preprocessing import preprocess_pipeline
    from src.evaluation import evaluate_model, print_evaluation_summary
except ImportError:
    from generate_dataset import create_dataset
    from preprocessing import preprocess_pipeline
    from evaluation import evaluate_model, print_evaluation_summary


def train_and_compare_models(data_path: str = 'data/raw/phishing_dataset.csv', models_dir: str = 'models'):
    """
    Complete ML training flow: dataset check -> preprocessing -> train 3 models -> evaluate -> save winner.
    """
    os.makedirs(models_dir, exist_ok=True)

    # 1. Ensure dataset exists
    if not os.path.exists(data_path):
        print(f"[!] Dataset not found at '{data_path}'. Generating synthetic dataset...")
        create_dataset(output_path=data_path, samples_per_class=1500)

    # 2. Preprocess dataset
    X_train, X_test, y_train, y_test, feature_names = preprocess_pipeline(raw_path=data_path)

    # 3. Define candidate models
    models = {
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
        'Decision Tree': DecisionTreeClassifier(random_state=42),
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42)
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model = None

    print("\n[+] Starting Model Training & Comparison...")

    for name, model in models.items():
        # Train model
        model.fit(X_train, y_train)
        
        # Evaluate model
        metrics = evaluate_model(model, X_test, y_test, model_name=name)
        results[name] = metrics
        print_evaluation_summary(metrics)

        # Track best model based on F1-score
        if metrics['f1_score'] > best_f1:
            best_f1 = metrics['f1_score']
            best_model_name = name
            best_model = model

    print(f"[*] Best Performing Model: {best_model_name} (F1 Score: {best_f1:.4f})")

    # 4. Extract feature importances if applicable
    feature_importances = {}
    if hasattr(best_model, 'feature_importances_'):
        importances = best_model.feature_importances_
        feature_importances = dict(sorted(
            zip(feature_names, [round(float(imp), 4) for imp in importances]),
            key=lambda x: x[1],
            reverse=True
        ))

    # 5. Save model artifacts
    model_filepath = os.path.join(models_dir, 'phishing_model.pkl')
    features_filepath = os.path.join(models_dir, 'feature_names.json')
    metrics_filepath = os.path.join(models_dir, 'model_metrics.json')

    # Save model binary
    joblib.dump(best_model, model_filepath)
    print(f"[+] Saved best model ({best_model_name}) to '{model_filepath}'")

    # Save feature names order
    with open(features_filepath, 'w') as f:
        json.dump(feature_names, f, indent=2)
    print(f"[+] Saved feature names list to '{features_filepath}'")

    # Save complete evaluation report JSON
    report_data = {
        'best_model': best_model_name,
        'all_models': results,
        'feature_importances': feature_importances
    }
    with open(metrics_filepath, 'w') as f:
        json.dump(report_data, f, indent=2)
    print(f"[+] Saved evaluation report to '{metrics_filepath}'\n")

    return best_model, results, feature_names


if __name__ == '__main__':
    train_and_compare_models()
