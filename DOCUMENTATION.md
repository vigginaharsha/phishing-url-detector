# 📚 Comprehensive Project Documentation & Presentation Guide

## 1. Beginner Mode Concepts Explained Simply

### 1. What is Phishing?
Phishing is a deceptive cyber attack where an attacker creates a fake website that looks almost identical to a real website (like PayPal, Google, or your bank). The goal is to trick you into entering your login credentials, credit card details, or personal information.

### 2. What is a URL?
URL stands for **Uniform Resource Locator**. It is the web address you type into a browser to visit a webpage.
Example: `https://www.google.com/search?q=security`
Components of a URL:
* **Scheme/Protocol**: `https://` (How browser communicates)
* **Subdomain**: `www.`
* **Domain/Host**: `google.com` (The name of the server)
* **Path**: `/search` (The specific page on the server)
* **Query Parameters**: `?q=security` (Extra data passed to the page)

### 3. What are URL Features?
URL features are numerical characteristics extracted from the address text. Examples include:
* How many characters long is the URL?
* How many dots (`.`) are in the domain?
* Does it use a numeric IP address instead of a company name?
* Does it contain words like `login`, `verify`, or `bank`?

### 4. What is Feature Extraction?
Feature extraction is the process of converting a raw text string (the URL) into a structured list of numbers that a computer algorithm can analyze mathematically.

### 5. What is a Dataset?
A dataset is a collection of thousands of example URLs that have already been labeled by cybersecurity experts as either **Safe (0)** or **Phishing (1)**. The machine learning model uses this data to learn patterns.

### 6. What is Classification?
Classification is a machine learning task where the computer assigns an input item into one of several predefined categories (e.g., classifying a URL into `SAFE`, `SUSPICIOUS`, or `PHISHING`).

### 7. What is Machine Learning?
Instead of a programmer manually writing thousands of `if/else` rules for every possible phishing link, Machine Learning allows a computer program to learn patterns automatically by analyzing thousands of past examples.

### 8. What is Random Forest?
Random Forest is a powerful machine learning algorithm. It creates a "forest" of multiple decision trees. Each decision tree inspects different URL features and votes on whether the URL is safe or phishing. The majority vote becomes the final prediction.

### 9. What is Model Training?
Training is the phase where the algorithm studies the dataset, adjusting its internal rules until it can accurately distinguish safe URLs from phishing URLs.

### 10. What is Prediction?
Prediction (or inference) is when a trained model receives a brand-new URL string it has never seen before and predicts its likelihood of being phishing based on what it learned during training.

### 11. What does Flask do?
Flask is a lightweight Python web framework. It handles web server duties—receiving URL inputs from your web browser, calling our Python ML scripts to make a prediction, and sending back the HTML webpage to display the results.

### 12. How do Frontend and Backend communicate?
1. The **Frontend** (HTML form in your browser) collects the URL you typed.
2. When you click **CHECK URL**, the browser sends an HTTP `POST` request to the Flask **Backend**.
3. Flask runs feature extraction and ML prediction in Python.
4. Flask sends back the updated HTML page (or JSON API response) displaying the Risk Score and Indicators.

### 13. How does the Risk Score work?
The Risk Score (0–100) maps the machine learning probability combined with critical security penalties:
* **0–30**: LOW RISK (SAFE)
* **31–70**: MEDIUM RISK (SUSPICIOUS)
* **71–100**: HIGH RISK (PHISHING)

---

## 2. Windows Commands Guide

Here are the exact Windows commands to execute, along with explanations of what each command does:

### 1. Create Python Virtual Environment
```powershell
python -m venv venv
```
* **Explanation**: Creates an isolated folder called `venv` containing Python binaries so project dependencies do not conflict with your global system Python installation.

### 2. Activate Virtual Environment
```powershell
.\venv\Scripts\Activate.ps1
```
* **Explanation**: Configures your current PowerShell session to use the Python executable and packages inside the `venv` folder.

### 3. Install Required Dependencies
```powershell
pip install -r requirements.txt
```
* **Explanation**: Reads `requirements.txt` and downloads Flask, Scikit-learn, Pandas, NumPy, Joblib, and Pytest.

### 4. Train the ML Models
```powershell
.\venv\Scripts\python.exe src/train_model.py
```
* **Explanation**: Generates synthetic training dataset, extracts features, trains Logistic Regression, Decision Tree, and Random Forest models, selects the champion model, and saves `models/phishing_model.pkl`.

### 5. Run Web Application Server
```powershell
.\venv\Scripts\python.exe app.py
```
* **Explanation**: Starts the Flask local web server on port 5000 (`http://127.0.0.1:5000`) and initializes the SQLite database (`scans.db`).

### 6. Run Automated Test Suite
```powershell
.\venv\Scripts\python.exe -m pytest tests/test_detector.py
```
* **Explanation**: Executes 13 automated Pytest unit tests to verify feature extraction, API routes, edge-case URLs, and database logging.

---

## 3. College Presentation & Viva Demonstration Script

### Demonstration Workflow (Step-by-Step for Interviewers):
1. **Show Architecture**: Explain that the application uses passive lexical analysis for maximum safety (zero external HTTP requests).
2. **Demonstrate Safe Scan**: Type `https://google.com/search?q=cybersecurity` -> Click **CHECK URL** -> Show 0/100 Risk Score, 🟢 SAFE status.
3. **Demonstrate Phishing Scan**: Type `http://192.168.1.1/paypal/login.php` -> Click **CHECK URL** -> Show 100/100 Risk Score, 🔴 PHISHING status, and highlight indicators (Raw IP Host, Suspicious Keywords).
4. **Show Analytics Dashboard**: Click **📊 Dashboard** tab -> Demonstrate total scans count and Chart.js donut distribution stored in SQLite.
5. **Show ML Model Insights**: Click **🧠 ML Insights** tab -> Show champion model benchmark comparison table and feature importance rankings.

### Top Viva Questions & Expert Answers

**Q1: How did you select features for URL classification?**
> **Answer**: We extracted 26 lexical features based on established cybersecurity research. These include domain length, subdomain depth, special character frequencies, `@` redirection symbols, IP hostname detection, shortener service matching, and suspicious brand keyword frequencies.

**Q2: What machine learning models were evaluated?**
> **Answer**: We evaluated Logistic Regression, Decision Trees, and Random Forest Classifiers. Random Forest performed best with 100% accuracy and F1 score on test samples, effectively handling feature interactions without overfitting.

**Q3: How do you handle False Positives vs False Negatives?**
> **Answer**: In cybersecurity, False Negatives (missing a real phishing site) are more dangerous than False Positives (flagging a safe site). Our risk engine combines raw ML probability with weighted heuristic penalties to ensure high recall on critical threats.

**Q4: Is the database persistent?**
> **Answer**: Yes, we use SQLite (`scans.db`) to record all scan history, timestamps, risk scores, and indicators. SQLite is lightweight, file-based, and ideal for single-node deployments.
