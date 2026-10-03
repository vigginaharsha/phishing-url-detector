"""
Flask Web Application for AI/ML Phishing URL Detection.

Provides web user interface, SQLite scan history database management,
analytics dashboard endpoints, and a secure REST API endpoint.
"""

import os
import json
import sqlite3
import re
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

from src.predict import PhishingPredictor, predict_url

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'phishing-detector-super-secret-key-2026')

DB_PATH = os.path.join(app.root_path, 'scans.db')

# Instantiate predictor engine
predictor = PhishingPredictor()


def get_db_connection():
    """
    Establishes connection to SQLite database and returns dictionary-like rows.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes SQLite database schema for storing scan history.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            indicators TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print(f"[DB] SQLite database initialized at '{DB_PATH}'.")


# Initialize DB on app launch
init_db()


def validate_url_input(url_str: str) -> tuple[bool, str]:
    """
    Validates user URL input for proper length, characters, and basic structure.
    Returns (is_valid, error_message).
    """
    if not url_str or not url_str.strip():
        return False, "Please enter a URL to scan."
    
    clean_url = url_str.strip()
    
    if len(clean_url) > 2048:
        return False, "URL exceeds maximum allowed length of 2048 characters."

    # Check for basic invalid strings like single words without dot or protocol
    # e.g., "abc", "not-a-url"
    if not clean_url.startswith(('http://', 'https://', 'ftp://')):
        test_url = 'http://' + clean_url
    else:
        test_url = clean_url

    parsed = urlparse(test_url)
    
    # Must have a valid network location containing at least one dot or be an IP address
    netloc = parsed.netloc.split(':')[0]  # strip port
    
    if not netloc:
        return False, "Please enter a valid URL format (e.g., https://example.com/login)."

    # Allow localhost, IP addresses, or domains with a dot
    is_ip = re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', netloc)
    is_domain_with_dot = '.' in netloc
    is_localhost = netloc.lower() in ('localhost', '127.0.0.1')

    if not (is_ip or is_domain_with_dot or is_localhost):
        return False, "Invalid URL structure. Please enter a valid hostname or domain."

    return True, ""


def save_scan_to_db(result: dict):
    """
    Saves a scan prediction result to SQLite database.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_history (url, prediction, risk_score, scanned_at, indicators)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            result['url'],
            result['prediction'],
            result['risk_score'],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            json.dumps(result['indicators'])
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Error logging scan to SQLite DB: {e}")


# ==================== WEB ROUTES ====================

@app.route('/')
def index():
    """
    Home Page - URL scanner form & model status badge.
    """
    model_trained = predictor.model is not None
    return render_template('index.html', model_trained=model_trained)


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Process URL input form submission.
    """
    raw_url = request.form.get('url', '').strip()
    
    is_valid, err_msg = validate_url_input(raw_url)
    if not is_valid:
        flash(err_msg, 'danger')
        return redirect(url_for('index'))

    # Run ML prediction & risk scoring engine
    result = predictor.predict(raw_url)
    
    # Save to SQLite database
    save_scan_to_db(result)
    
    return render_template('result.html', result=result)


@app.route('/dashboard')
def dashboard():
    """
    Analytics Dashboard Page - Recent scans, statistics summary, and risk distribution.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total scans count
    cursor.execute('SELECT COUNT(*) FROM scan_history')
    total_scans = cursor.fetchone()[0]
    
    # Breakdown by prediction
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE prediction = 'SAFE'")
    safe_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE prediction = 'SUSPICIOUS'")
    suspicious_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE prediction = 'PHISHING'")
    phishing_count = cursor.fetchone()[0]
    
    # Recent scans (latest 15)
    cursor.execute('SELECT * FROM scan_history ORDER BY id DESC LIMIT 15')
    recent_scans = cursor.fetchall()
    
    conn.close()
    
    stats = {
        'total': total_scans,
        'safe': safe_count,
        'suspicious': suspicious_count,
        'phishing': phishing_count
    }
    
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)


@app.route('/model-insights')
def model_insights():
    """
    ML Model Information & Metrics Comparison Page.
    """
    metrics_path = os.path.join(app.root_path, 'models', 'model_metrics.json')
    report_data = None
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, 'r') as f:
                report_data = json.load(f)
        except Exception as e:
            print(f"[!] Failed to read model_metrics.json: {e}")
            
    return render_template('model_insights.html', report=report_data)


# ==================== REST API ENDPOINT ====================

@app.route('/api/predict', methods=['POST'])
def api_predict():
    """
    API Endpoint for URL analysis.
    
    Request JSON:
        { "url": "https://example.com/login" }
        
    Response JSON:
        {
            "url": "https://example.com/login",
            "prediction": "SAFE",
            "risk_score": 12,
            "risk_level": "LOW RISK",
            "confidence": 0.082,
            "indicators": [...]
        }
    """
    if not request.is_json:
        return jsonify({
            "error": "Invalid request content-type. Expected 'application/json'."
        }), 400

    data = request.get_json()
    url_str = data.get('url', '')

    is_valid, err_msg = validate_url_input(url_str)
    if not is_valid:
        return jsonify({
            "error": err_msg,
            "prediction": "INVALID",
            "risk_score": 0
        }), 400

    result = predictor.predict(url_str)
    save_scan_to_db(result)

    return jsonify({
        "url": result['url'],
        "prediction": result['prediction'],
        "risk_score": result['risk_score'],
        "risk_level": result['risk_level'],
        "confidence": result['confidence'],
        "indicators": result['indicators']
    }), 200


if __name__ == '__main__':
    print("[+] Starting Phishing URL Detection Web Application...")
    app.run(host='127.0.0.1', port=5000, debug=True)
