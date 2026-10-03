"""
Unit and Integration Tests for AI Phishing URL Detection System.

Tests cover lexical feature extraction, edge-case URLs, prediction logic,
Flask routes, and REST API validation.
"""

import pytest
import json
from app import app, init_db
from src.feature_extraction import extract_features, extract_indicators, is_ip_address
from src.predict import predict_url, PhishingPredictor


@pytest.fixture
def client():
    """
    Test fixture providing a Flask test client with initialized database.
    """
    app.config['TESTING'] = True
    init_db()
    with app.test_client() as client:
        yield client


class TestFeatureExtraction:
    """
    Tests for lexical feature extraction engine.
    """

    def test_ip_address_detection(self):
        assert is_ip_address("192.168.1.1") is True
        assert is_ip_address("10.0.0.1:8080") is True
        assert is_ip_address("google.com") is False
        assert is_ip_address("paypal-security.com") is False

    def test_lexical_features_safe_url(self):
        url = "https://google.com/search?q=cybersecurity"
        feats = extract_features(url)
        assert feats['has_https'] == 1
        assert feats['has_ip'] == 0
        assert feats['has_at_symbol'] == 0
        assert feats['num_subdomains'] == 0
        assert feats['url_length'] > 0

    def test_lexical_features_phishing_ip(self):
        url = "http://192.168.1.1/paypal/login.php?user=verify"
        feats = extract_features(url)
        assert feats['has_ip'] == 1
        assert feats['suspicious_keyword_count'] >= 2
        assert feats['has_https'] == 0

    def test_at_symbol_detection(self):
        url = "http://legitimate.com@phishing-target.info/login"
        feats = extract_features(url)
        assert feats['has_at_symbol'] == 1

    def test_excessive_subdomains(self):
        url = "https://secure.auth.account.verify.paypal.fake-domain.com/login"
        feats = extract_features(url)
        assert feats['num_subdomains'] >= 4


class TestPredictionEngine:
    """
    Tests for risk score calculation & prediction classification.
    """

    def test_safe_url_prediction(self):
        url = "https://example.com/login"
        res = predict_url(url)
        assert res['prediction'] in ["SAFE", "SUSPICIOUS", "PHISHING"]
        assert 0 <= res['risk_score'] <= 100
        assert 'indicators' in res

    def test_ip_based_url_risk_score(self):
        url = "http://192.168.1.1/paypal/login.php?user=verify"
        res = predict_url(url)
        # IP + suspicious keywords should trigger high risk or phishing prediction
        assert res['risk_score'] >= 50
        assert any(ind['title'] == 'IP Address Hostname' for ind in res['indicators'])

    def test_shortener_url_indicator(self):
        url = "http://bit.ly/3x9Z10"
        res = predict_url(url)
        assert any(ind['title'] == 'URL Shortening Service' for ind in res['indicators'])


class TestFlaskEndpoints:
    """
    Integration tests for web routes and REST API endpoint.
    """

    def test_index_route(self, client):
        response = client.get('/')
        assert response.status_code == 200
        assert b"Phishing URL" in response.data or b"Analyze" in response.data

    def test_dashboard_route(self, client):
        response = client.get('/dashboard')
        assert response.status_code == 200
        assert b"Scan Analytics Dashboard" in response.data

    def test_analyze_valid_form(self, client):
        response = client.post('/analyze', data={'url': 'https://google.com'}, follow_redirects=True)
        assert response.status_code == 200
        assert b"Scanned URL Target" in response.data or b"SAFE" in response.data

    def test_analyze_empty_form(self, client):
        response = client.post('/analyze', data={'url': ''}, follow_redirects=True)
        assert response.status_code == 200
        assert b"Please enter a URL to scan" in response.data

    def test_api_predict_success(self, client):
        payload = {"url": "https://example.com/login"}
        response = client.post(
            '/api/predict',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "prediction" in data
        assert "risk_score" in data
        assert "indicators" in data
        assert data["url"] == "https://example.com/login"

    def test_api_predict_invalid_content_type(self, client):
        response = client.post('/api/predict', data="not json")
        assert response.status_code == 400
        assert b"Invalid request content-type" in response.data

    def test_api_predict_invalid_url(self, client):
        payload = {"url": "abc"}
        response = client.post(
            '/api/predict',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
