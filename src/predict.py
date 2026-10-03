"""
Prediction & Risk Scoring Engine for Phishing Detection.

Loads trained machine learning model and feature list, executes inference on incoming URLs,
computes 0-100 risk score, categorizes risk level, and generates explanations.
"""

import os
import sys
import json
import joblib
import pandas as pd

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.feature_extraction import extract_features, extract_indicators
except ImportError:
    from feature_extraction import extract_features, extract_indicators


class PhishingPredictor:
    def __init__(self, model_dir: str = 'models'):
        self.model_dir = model_dir
        self.model_path = os.path.join(model_dir, 'phishing_model.pkl')
        self.features_path = os.path.join(model_dir, 'feature_names.json')
        self.model = None
        self.feature_names = None
        self.load_model()

    def load_model(self):
        """
        Loads trained model binary and feature column ordering.
        """
        if os.path.exists(self.model_path) and os.path.exists(self.features_path):
            try:
                self.model = joblib.load(self.model_path)
                with open(self.features_path, 'r') as f:
                    self.feature_names = json.load(f)
                print(f"[Predictor] Loaded ML model successfully from '{self.model_path}'.")
            except Exception as e:
                print(f"[!] Error loading model: {e}. Will rely on rule-based fallback.")
                self.model = None
        else:
            print(f"[!] Warning: Trained model not found at '{self.model_path}'. Call src/train_model.py to train one.")
            self.model = None

    def calculate_risk_score(self, model_prob: float, features: dict) -> int:
        """
        Computes application-level risk score (0-100) combining ML probability with critical heuristic flags.
        """
        # Base ML probability score (0 to 100)
        base_score = int(model_prob * 100)

        # Critical heuristic security adjustments
        heuristics_penalty = 0

        # Raw IP hostname is a strong threat flag (+25)
        if features.get('has_ip') == 1:
            heuristics_penalty += 25

        # @ symbol obfuscation (+20)
        if features.get('has_at_symbol') == 1:
            heuristics_penalty += 20

        # Excessive subdomains (+15)
        if features.get('num_subdomains', 0) >= 3:
            heuristics_penalty += 15

        # Shorteners (+10)
        if features.get('is_url_shortener') == 1:
            heuristics_penalty += 10

        # Punycode spoofing (+20)
        if features.get('has_punycode') == 1:
            heuristics_penalty += 20

        # Combine ML base score with heuristic penalties
        if self.model is not None:
            # Weighted mix: 75% ML probability + 25% heuristic boost
            combined_score = int(base_score * 0.75 + min(100, base_score + heuristics_penalty) * 0.25)
        else:
            # Fallback score if ML model is missing
            combined_score = min(100, base_score + heuristics_penalty)

        # Cap score between 0 and 100
        risk_score = max(0, min(100, combined_score))
        return risk_score

    def predict(self, url_string: str) -> dict:
        """
        Main inference pipeline for a URL string.
        
        Returns:
            dict containing:
                - url
                - prediction ("SAFE", "SUSPICIOUS", "PHISHING")
                - risk_score (0-100)
                - risk_level ("LOW RISK", "MEDIUM RISK", "HIGH RISK")
                - confidence (probability score)
                - indicators (list of explanations)
                - features (extracted raw lexical features)
        """
        # 1. Extract numerical features
        features_dict = extract_features(url_string)
        
        # 2. Extract human-readable UI indicators
        indicators = extract_indicators(url_string, features_dict)

        # 3. Model Inference or Fallback
        if self.model is not None and self.feature_names is not None:
            # Construct DataFrame with exact column ordering expected by model
            df_input = pd.DataFrame([features_dict])[self.feature_names]
            
            # Predict probability of phishing (class 1)
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(df_input)[0]
                phish_prob = float(probs[1])
            else:
                pred_class = self.model.predict(df_input)[0]
                phish_prob = 1.0 if pred_class == 1 else 0.0
        else:
            # Rule-based fallback if ML model binary is missing
            danger_count = sum(1 for ind in indicators if ind['status'] == 'danger')
            warning_count = sum(1 for ind in indicators if ind['status'] == 'warning')
            phish_prob = min(1.0, (danger_count * 0.35 + warning_count * 0.15))

        # 4. Risk Score & Level Calculation
        risk_score = self.calculate_risk_score(phish_prob, features_dict)

        if risk_score <= 30:
            prediction = "SAFE"
            risk_level = "LOW RISK"
        elif risk_score <= 70:
            prediction = "SUSPICIOUS"
            risk_level = "MEDIUM RISK"
        else:
            prediction = "PHISHING"
            risk_level = "HIGH RISK"

        return {
            'url': url_string,
            'prediction': prediction,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': round(phish_prob, 4),
            'indicators': indicators,
            'features': features_dict
        }


# Singleton instance for quick reuse across Flask requests
predictor_instance = PhishingPredictor()


def predict_url(url_string: str) -> dict:
    return predictor_instance.predict(url_string)


if __name__ == '__main__':
    # Quick test demonstration
    test_urls = [
        "https://google.com/search?q=cybersecurity",
        "http://192.168.1.1/paypal/login.php?user=verify",
        "http://bit.ly/3x9Z10"
    ]
    for u in test_urls:
        res = predict_url(u)
        print(f"URL: {res['url']} => [{res['prediction']}] Risk Score: {res['risk_score']}/100")
