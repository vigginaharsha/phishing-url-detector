"""
Production Server Launcher using Waitress WSGI (Windows & Cross-Platform)
"""

import sys
import os
from waitress import serve
from app import app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"\n========================================================")
    print(f" 🛡️  AI Phishing URL Detector - Production Server")
    print(f"========================================================")
    print(f" [+] Server Running at: http://127.0.0.1:{port}")
    print(f" [+] Threads: 4 | Host: 0.0.0.0 (Local & Network access)")
    print(f" [+] Press Ctrl+C to stop the server.")
    print(f"========================================================\n")
    serve(app, host='0.0.0.0', port=port, threads=4)
