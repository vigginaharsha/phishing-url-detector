# 🛡️ AI/ML Phishing URL Detection System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0.2-black?logo=flask)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4.1-orange?logo=scikit-learn)
![SQLite](https://img.shields.io/badge/SQLite-3.0-003B57?logo=sqlite)
![Status](https://img.shields.io/badge/Status-Production%20Ready-emerald)

An end-to-end, cybersecurity-themed **AI/ML Phishing URL Detection Web Application**. This system analyzes incoming web URLs as text strings using 26 lexical features (length, subdomains, character frequencies, suspicious keywords, IP hostnames, URL shorteners, etc.) and predicts whether a URL is **SAFE**, **SUSPICIOUS**, or **PHISHING**, computing a 0–100 risk score with human-readable security indicators.

> ⚠️ **Safety Guarantee**: This application operates strictly offline on URL strings. It **never** requests, opens, crawls, or executes submitted links, protecting users from live web threats.

---

## 📋 Table of Contents
1. [Project Overview](#1-project-overview)
2. [Problem Statement & Objectives](#2-problem-statement--objectives)
3. [Key Features](#3-key-features)
4. [Technology Stack](#4-technology-stack)
5. [System Architecture](#5-system-architecture)
6. [Project Structure](#6-project-structure)
7. [Installation & Setup](#7-installation--setup)
8. [Dataset & Preprocessing](#8-dataset--preprocessing)
9. [Machine Learning Model Pipeline](#9-machine-learning-model-pipeline)
10. [Risk Scoring & Indicator Engine](#10-risk-scoring--indicator-engine)
11. [Running the Web Application](#11-running-the-web-application)
12. [REST API Documentation](#12-rest-api-documentation)
13. [Automated Testing](#13-automated-testing)
14. [Beginner's Guide & Core Concepts](#14-beginners-guide--core-concepts)
15. [College Project & Viva Q&A](#15-college-project--viva-qa)
16. [Limitations](#16-limitations)
17. [Future Enhancements](#17-future-enhancements)
18. [Ethical & Safety Considerations](#18-ethical--safety-considerations)
19. [Screenshots Overview](#19-screenshots-overview)
20. [Author & License](#20-author--license)

---

## 1. Project Overview
Phishing remains one of the most widespread social engineering attack vectors, luring users to malicious websites designed to steal credentials, banking tokens, and personal data. This project leverages machine learning lexical classification to detect suspicious structural patterns in URLs without interacting with dangerous remote servers.

---

## 2. Problem Statement & Objectives

### Problem Statement
Attackers frequently register lookalike domains, obscure target destinations using URL shorteners, deploy raw IP hostnames, or embed deceptive subdomains (e.g., `secure-login.paypal-verify-update.com`). Traditional blacklist databases often fail to identify brand-new (zero-day) phishing links.

### Objectives
* **Detect zero-day phishing attempts** using string feature patterns.
* **Train & benchmark ML algorithms** (Logistic Regression, Decision Trees, Random Forest).
* **Calculate a 0–100 Threat Risk Score**.
* **Provide clear security reason indicators** for every scan.
* **Maintain persistent SQLite scan history** and an interactive analytics dashboard.
* **Expose a REST API** (`POST /api/predict`) for programmatically analyzing URLs.

---

## 3. Key Features
* 🔬 **26 Lexical URL Features**: Analyzes domain length, subdomains, special character ratios, `@` redirects, IP addresses, suspicious keywords, and encoding.
* 🤖 **Machine Learning Classifier**: Multi-model comparison pipeline selecting the optimal classifier based on cross-validation F1-Score.
* 🛡️ **Zero Remote Interaction**: 100% safe offline parsing without web requests or crawling.
* 📊 **SQLite Analytics Dashboard**: Displays historical scans, class distribution donut charts, and scan logs.
* 🎨 **Cybersecurity UI/UX**: Dark mode glassmorphism UI built with modern HTML5/CSS3/JavaScript.
* 🔌 **REST API**: Accessible JSON endpoint for automated integrations.
* 🧪 **Automated Test Suite**: 13 unit/integration tests using Pytest.

---

## 4. Technology Stack
* **Frontend**: HTML5, Vanilla CSS3 (Custom Glassmorphism Design System), JavaScript (ES6+), Chart.js.
* **Backend**: Python 3.10+, Flask 3.0+.
* **Machine Learning**: Scikit-Learn, Pandas, NumPy, Joblib.
* **Database**: SQLite 3 (`scans.db`).
* **Testing**: Pytest.

---

## 5. System Architecture

```
User / API Client
       │
       ▼
 ┌───────────┐       Validates String       ┌─────────────────────────┐
 │ Flask App │ ───────────────────────────► │ Feature Extractor       │
 └─────┬─────┘                              │ (26 Lexical Features)   │
       │                                    └────────────┬────────────┘
       │                                                 │
       │                                                 ▼
       │                                    ┌─────────────────────────┐
       │                                    │ Random Forest Classifier│
       │                                    │ (phishing_model.pkl)    │
       │                                    └────────────┬────────────┘
       │                                                 │
       │                                                 ▼
       │                                    ┌─────────────────────────┐
       │                                    │ Risk & Indicator Engine │
       │                                    │ (0-100 Score + Reasons) │
       │                                    └────────────┬────────────┘
       │                                                 │
       ▼                                                 │
 ┌───────────┐ <─────────────────────────────────────────┘
 │ SQLite DB │  (Stores scan output & timestamp)
 └───────────┘
```

---

## 6. Project Structure

```
phishing-url-detector/
│
├── app.py                      # Main Flask application & API routes
├── requirements.txt            # Python dependency definitions
├── README.md                   # Comprehensive project manual
├── .gitignore                  # Git exclude rules
├── scans.db                    # SQLite scan history database
│
├── data/
│   ├── raw/
│   │   └── phishing_dataset.csv # Raw URL dataset (3,000 samples)
│   └── processed/
│
├── models/
│   ├── phishing_model.pkl      # Saved champion Random Forest model
│   ├── feature_names.json      # Column ordering index
│   └── model_metrics.json      # Model benchmark evaluation metrics
│
├── notebooks/                  # Directory for Jupyter experiments
│
├── src/
│   ├── __init__.py
│   ├── feature_extraction.py   # Lexical URL parser & feature extractor
│   ├── generate_dataset.py     # Dataset builder module
│   ├── preprocessing.py        # Data cleaning & train/test split
│   ├── train_model.py          # ML training & evaluation workflow
│   ├── predict.py              # Risk scoring & explanation engine
│   └── evaluation.py           # Metrics calculation helper
│
├── templates/
│   ├── base.html               # Navigation bar & layout template
│   ├── index.html              # URL Scanner form page
│   ├── result.html             # Detailed scan result page
│   ├── dashboard.html          # SQLite Analytics & Chart.js dashboard
│   └── model_insights.html     # ML Benchmark comparison page
│
├── static/
│   ├── css/
│   │   └── style.css           # Glassmorphism cyber design system
│   └── js/
│       └── script.js            # Client-side form helpers & animation
│
└── tests/
    └── test_detector.py        # Automated test suite
```

---

## 7. Installation & Setup

### Prerequisites
* Python 3.10 or higher installed on Windows/Linux/macOS.

### Windows Installation Steps
Open Windows PowerShell inside the project directory:

1. **Create Virtual Environment**:
   ```powershell
   python -m venv venv
   ```

2. **Activate Environment**:
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

3. **Install Dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

---

## 8. Dataset & Preprocessing

The project includes a dataset generator (`src/generate_dataset.py`) that constructs a balanced dataset of 3,000 URLs (1,500 Safe, 1,500 Phishing).

### Running Preprocessing:
```powershell
.\venv\Scripts\python.exe src/preprocessing.py
```
* **Hygiene**: Removes null values and duplicate URLs to prevent data leakage.
* **Feature Generation**: Transforms URL text into a 26-column numerical matrix.
* **Stratified Split**: 80% Training set (2,400 rows), 20% Test set (600 rows).

---

## 9. Machine Learning Model Pipeline

The model training script (`src/train_model.py`) trains and compares 3 classifiers:
1. **Logistic Regression** (Linear baseline)
2. **Decision Tree Classifier** (Non-linear rule tree)
3. **Random Forest Classifier** (Ensemble of 100 decision trees)

### Train & Evaluate Models:
```powershell
.\venv\Scripts\python.exe src/train_model.py
```

### Benchmark Results (Measured Test Data):
| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 99.76% | 99.58% | 100.00% | 99.79% | 1.0000 | Evaluated |
| **Decision Tree** | 99.76% | 99.58% | 100.00% | 99.79% | 0.9973 | Evaluated |
| **Random Forest** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **1.0000** | 🏆 Champion |

---

## 10. Risk Scoring & Indicator Engine

Risk scores (0–100) combine ML model probability output $P(\text{phishing})$ with heuristic security flags:

$$\text{Risk Score} = \min\left(100, \, \text{Base ML Score} + \text{Heuristic Penalties}\right)$$

### Risk Categories:
* **0 – 30**: 🟢 **SAFE (LOW RISK)**
* **31 – 70**: 🟡 **SUSPICIOUS (MEDIUM RISK)**
* **71 – 100**: 🔴 **PHISHING (HIGH RISK)**

---

## 11. Running the Web Application

Launch the Flask development server:
```powershell
.\venv\Scripts\python.exe app.py
```
Open your browser and visit:
👉 `http://127.0.0.1:5000`

---

## 12. REST API Documentation

### Analyze URL Endpoint
* **URL**: `POST /api/predict`
* **Headers**: `Content-Type: application/json`

#### Example Request:
```bash
curl -X POST http://127.0.0.1:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1/paypal/login.php"}'
```

#### Example Response:
```json
{
  "confidence": 1.0,
  "indicators": [
    {
      "description": "URL uses a raw IP address instead of a domain name.",
      "icon": "⚠",
      "status": "danger",
      "title": "IP Address Hostname"
    },
    {
      "description": "Detected potential sensitive targets: login, paypal.",
      "icon": "⚠",
      "status": "danger",
      "title": "Suspicious Keyword(s)"
    }
  ],
  "prediction": "PHISHING",
  "risk_level": "HIGH RISK",
  "risk_score": 100,
  "url": "http://192.168.1.1/paypal/login.php"
}
```

---

## 13. Automated Testing

Run the automated Pytest test suite:
```powershell
.\venv\Scripts\python.exe -m pytest tests/test_detector.py
```
Outputs test confirmation across feature extraction, risk scoring, route status, and API error handling.

---

## 14. Beginner's Guide & Core Concepts

1. **What is Phishing?** A cyber attack where fraudulent web pages impersonate trustworthy organizations to trick users into revealing sensitive data.
2. **What is a URL?** Uniform Resource Locator (e.g., `https://sub.example.com:443/login?id=1#top`).
3. **What is Feature Extraction?** Converting raw URL strings into numerical numbers (counts of slashes, dots, hyphens, ratios) that ML algorithms can compute.
4. **What is Random Forest?** An ensemble machine learning algorithm combining multiple decision trees to vote on the final prediction, reducing overfitting.
5. **What is Flask?** A lightweight Python web framework that handles HTTP web routing between frontend browsers and Python backend logic.

---

## 15. College Project & Viva Q&A

### Q1: Why not use a simple blacklist database?
> **Answer**: Blacklists require prior discovery. Attackers launch thousands of temporary zero-day URLs daily. Lexical ML models detect zero-day phishing based on structural anomalies.

### Q2: Why is Accuracy insufficient for evaluating phishing models?
> **Answer**: In security, **Recall** (catching real phishing attacks) and **Precision** (avoiding false alarms on safe sites) are far more critical than raw accuracy. A model with 95% accuracy that misses 50% of phishing links is dangerous.

### Q3: Why is passive string analysis safer than crawling URLs?
> **Answer**: Crawling or loading remote web pages exposes the server to drive-by malware downloads, malicious scripts, and alerts the attacker that their phishing link is being investigated.

---

## 16. Limitations
* **Pure Lexical Scope**: Does not inspect live webpage DOM content or SSL certificate validity.
* **Obfuscation**: Advanced obfuscation or JavaScript redirects may alter landing destinations.

---

## 17. Future Enhancements
* 🌐 **DNS & WHOIS Integration**: Incorporate domain age and registrar data.
* 🔌 **Browser Extension**: Real-time Chrome/Firefox toolbar indicator.
* 🤖 **Explainable AI (SHAP)**: Granular feature contribution plots.

---

## 18. Ethical & Safety Considerations
This system is created purely for educational, defensive cybersecurity research. It uses safe synthetic and public research datasets without visiting or interacting with live malicious infrastructure.

---

## 19. Screenshots Overview
* **Home Page**: Cyber Scanner input form with quick-fill sample presets.
* **Scan Results**: Dynamic Risk Score gauge, SAFE/PHISHING status badge, and reason cards.
* **Analytics Dashboard**: SQLite scan logs and Chart.js donut distribution.
* **ML Insights**: Model evaluation tables and feature importance rankings.

---

## 20. Author & License
* **Project**: AI/ML Phishing URL Detector
* **License**: MIT License
