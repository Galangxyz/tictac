from flask import Flask, render_template, request, abort, jsonify
import requests
import time

app = Flask(__name__)

# In-memory storage untuk rate limiting sederhana
ip_requests = {}

# Cloudflare Turnstile Secret Key
TURNSTILE_SECRET_KEY = "0x4AAAAAAAygR-UykD6sJFXT"

@app.before_request
def advanced_bot_protection():
    # Filtering User-Agent
    user_agent = request.headers.get("User-Agent", "").lower()
    blocked_agents = ["bot", "curl", "scrapy", "httpclient"]
    if any(bot in user_agent for bot in blocked_agents):
        abort(403)  # Bot terdeteksi, akses ditolak
    
    # Rate limiting sederhana per IP
    ip = request.remote_addr
    current_time = time.time()
    
    # Check if IP is in the request log
    if ip in ip_requests:
        ip_requests[ip].append(current_time)
    else:
        ip_requests[ip] = [current_time]
    
    # Hapus permintaan lebih lama dari 1 menit
    ip_requests[ip] = [t for t in ip_requests[ip] if current_time - t < 60]
    
    # Batasi maksimal 20 permintaan per menit
    if len(ip_requests[ip]) > 20:
        abort(429)  # Terlalu banyak permintaan, akses ditolak

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/verify-captcha', methods=['POST'])
def verify_captcha():
    token = request.form.get('cf-turnstile-response')
    if not token:
        return jsonify({"success": False, "message": "No CAPTCHA token provided"}), 400

    # Verifikasi token dengan Cloudflare
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {
        'secret': TURNSTILE_SECRET_KEY,
        'response': token
    }
    response = requests.post(url, data=data)
    result = response.json()

    if result.get("success"):
        return jsonify({"success": True, "message": "CAPTCHA verified"})
    else:
        return jsonify({"success": False, "message": "CAPTCHA verification failed"}), 400

if __name__ == "__main__":
    app.run(debug=True)
