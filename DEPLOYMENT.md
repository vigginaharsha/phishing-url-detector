# 🚀 Deployment Guide: AI Phishing URL Detector

This guide provides step-by-step instructions for deploying the **AI/ML Phishing URL Detector** across various production environments: Render, Docker, Windows Waitress Production Server, and Ubuntu VPS (Nginx + Gunicorn).

---

## 📋 Option 1: One-Click Deploy to Render (Recommended - Free Cloud Hosting)

Render provides free hosting for web applications with automated Git deployments.

### Steps:
1. **Push your code to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit of Phishing URL Detector"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/phishing-url-detector.git
   git push -u origin main
   ```
2. **Create a New Web Service on Render**:
   - Log in to [Render.com](https://render.com).
   - Click **New +** -> **Web Service**.
   - Connect your GitHub repository.
3. **Configure Render Settings**:
   - **Name**: `phishing-url-detector`
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt && python src/train_model.py`
   - **Start Command**: `gunicorn wsgi:app`
4. **Click "Create Web Service"**: Render will build the environment, train the ML model inside the container, and deploy your live URL endpoint (e.g., `https://phishing-url-detector.onrender.com`).

---

## 🐳 Option 2: Containerized Deployment with Docker

Containerizing ensures the application runs identically on any server, Cloud VM, AWS ECS, or Google Cloud Run.

### 1. Build the Docker Image:
```bash
docker build -t phishing-url-detector .
```

### 2. Run the Docker Container:
```bash
docker run -d -p 5000:5000 --name phishing_app phishing-url-detector
```

### 3. Verify:
Open your browser at `http://localhost:5000`.

---

## 🖥️ Option 3: Local Production Server on Windows (using Waitress)

For running a multi-threaded production server locally on Windows without Flask development warnings:

### 1. Install Dependencies:
```powershell
.\venv\Scripts\pip.exe install -r requirements.txt
```

### 2. Run Waitress Server:
```powershell
.\venv\Scripts\python.exe -c "from waitress import serve; from app import app; print('[+] Waitress server running on http://127.0.0.1:5000'); serve(app, host='127.0.0.1', port=5000, threads=4)"
```

---

## 🐧 Option 4: Deploying on an Ubuntu Linux VPS (Nginx + Gunicorn + Systemd)

For deploying to an AWS EC2 instance, DigitalOcean Droplet, or Linode server:

### 1. System Setup & Clone Repository:
```bash
sudo apt update && sudo apt install -y python3-pip python3-venv nginx git
git clone https://github.com/YOUR_USERNAME/phishing-url-detector.git
cd phishing-url-detector
```

### 2. Set Up Virtual Environment & Train Model:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python src/train_model.py
```

### 3. Create Systemd Service File (`/etc/systemd/system/phishing.service`):
```ini
[Unit]
Description=Gunicorn instance to serve Phishing URL Detector
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/home/ubuntu/phishing-url-detector
Environment="PATH=/home/ubuntu/phishing-url-detector/venv/bin"
ExecStart=/home/ubuntu/phishing-url-detector/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 wsgi:app

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl start phishing
sudo systemctl enable phishing
```

### 4. Configure Nginx Reverse Proxy (`/etc/nginx/sites-available/phishing`):
```nginx
server {
    listen 80;
    server_name your_domain_or_vps_ip;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Enable Nginx site configuration and restart Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/phishing /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🔒 Security Best Practices in Production
1. **Secret Key**: Set the `SECRET_KEY` environment variable on your server:
   ```bash
   export SECRET_KEY="your-random-production-secret-key"
   ```
2. **HTTPS**: If using a custom domain on Linux, install Certbot for free SSL:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com
   ```
