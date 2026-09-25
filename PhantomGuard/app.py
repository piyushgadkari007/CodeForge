
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import time
import random
import os
import secrets
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('PHANTOMGUARD_SECRET', 'phantomguard-demo-key')
app.config['GOOGLE_MAPS_API_KEY'] = os.environ.get('GOOGLE_MAPS_API_KEY', '')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = (
    os.environ.get('FLASK_ENV') == 'production'
    or bool(os.environ.get('RENDER'))
    or bool(os.environ.get('VERCEL'))
)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

project_root = Path(__file__).resolve().parent.parent
instance_dir = project_root / 'instance'
instance_dir.mkdir(exist_ok=True)


def get_database_uri():
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        return database_url
    if os.environ.get('VERCEL') == '1':
        return 'sqlite:////tmp/phantomguard.db'
    return f"sqlite:///{instance_dir / 'phantomguard.db'}"


app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


def get_upload_folder():
    if os.environ.get('VERCEL') == '1':
        upload_dir = Path('/tmp/phantomguard_uploads')
    else:
        upload_dir = project_root / 'uploads'
    upload_dir.mkdir(parents=True, exist_ok=True)
    return str(upload_dir)


UPLOAD_FOLDER = get_upload_folder()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # 50MB max-limit

db = SQLAlchemy(app)


@app.before_request
def require_admin_login():
    public_endpoints = {"login", "signup", "static"}
    if request.endpoint in public_endpoints or session.get("user_id"):
        return None
    if request.path.startswith("/api/") or request.path in {"/attack", "/status", "/reset"}:
        return jsonify({"error": "Admin login required."}), 401
    return redirect(url_for("login", next=request.path))

# ===== DATABASE MODEL =====
class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(128), nullable=False)
    device = db.Column(db.String(128), nullable=False)
    signal = db.Column(db.String(32), nullable=True)
    location = db.Column(db.String(128), nullable=True)
    lat = db.Column(db.Float, nullable=True)
    lon = db.Column(db.Float, nullable=True)
    action = db.Column(db.String(128), nullable=True)
    fake_data = db.Column(db.String(128), nullable=True)
    phone = db.Column(db.String(32), nullable=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# ===== GLOBAL STATES =====
attack_detected = False
attack_time = None
phone_alert = "SAFE"
attacker_lat = None
attacker_lon = None
attacker_location = "Unknown location"
attacker_ip = None
LOGIN_ATTEMPTS = defaultdict(deque)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 600
ATTEMPT_WINDOW_SECONDS = 300


def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown-ip'


def reset_login_attempts():
    LOGIN_ATTEMPTS.clear()


def is_ip_locked(ip):
    attempts = LOGIN_ATTEMPTS.get(ip, deque())
    now = time.time()
    while attempts and now - attempts[0] > ATTEMPT_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        return True
    return False


def record_failed_login_attempt():
    ip = get_client_ip()
    attempts = LOGIN_ATTEMPTS.setdefault(ip, deque())
    now = time.time()
    while attempts and now - attempts[0] > ATTEMPT_WINDOW_SECONDS:
        attempts.popleft()
    attempts.append(now)


@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; "
        "script-src 'self' 'unsafe-inline' https://maps.googleapis.com https://unpkg.com; "
        "connect-src 'self' https://maps.googleapis.com; "
        "frame-ancestors 'none';"
    )
    return response


def get_time_based_greeting(current_time=None):
    return "Hello"


# ===== HOME (DEFENDER DASHBOARD) =====
@app.route("/")
def home():
    user = User.query.get(session['user_id']) if session.get('user_id') else None
    greeting = get_time_based_greeting()
    return render_template("index.html", user=user, greeting=greeting, google_maps_api_key=app.config['GOOGLE_MAPS_API_KEY'])


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        session['csrf_token'] = secrets.token_urlsafe(32)
        return render_template("auth.html", mode="signup", csrf_token=session['csrf_token'])

    submitted_token = request.form.get("csrf_token")
    expected_token = session.get("csrf_token")
    if not expected_token or submitted_token != expected_token:
        flash("Security validation failed. Please refresh and try again.", "error")
        return render_template("auth.html", mode="signup", csrf_token=expected_token or secrets.token_urlsafe(32))

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not name or not email or len(password) < 6:
        flash("Enter your name, a valid email, and a password with 6+ characters.", "error")
    elif User.query.filter_by(email=email).first():
        flash("An account with that email already exists.", "error")
    else:
        user = User(name=name, email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        session.pop('csrf_token', None)
        return redirect(url_for("home"))
    return render_template("auth.html", mode="signup", csrf_token=expected_token)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        session['csrf_token'] = secrets.token_urlsafe(32)
        return render_template("auth.html", mode="login", csrf_token=session['csrf_token'])

    submitted_token = request.form.get("csrf_token")
    expected_token = session.get("csrf_token")
    if not expected_token or submitted_token != expected_token:
        flash("Security validation failed. Please refresh and try again.", "error")
        return render_template("auth.html", mode="login", csrf_token=expected_token or secrets.token_urlsafe(32))

    ip = get_client_ip()
    if is_ip_locked(ip):
        flash(f"Too many failed login attempts. Please wait {LOCKOUT_SECONDS // 60} minutes and try again.", "error")
        return render_template("auth.html", mode="login", csrf_token=session['csrf_token'])

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        LOGIN_ATTEMPTS.pop(ip, None)
        session['user_id'] = user.id
        session.pop('csrf_token', None)
        next_path = request.args.get("next") or request.form.get("next") or url_for("home")
        if not next_path.startswith('/') or next_path.startswith('//'):
            next_path = url_for("home")
        return redirect(next_path)

    record_failed_login_attempt()
    flash("Email or password is incorrect.", "error")
    return render_template("auth.html", mode="login", csrf_token=expected_token)


@app.route("/logout")
def logout():
    session.pop('user_id', None)
    return redirect(url_for("home"))

# ===== ATTACKER PANEL =====
@app.route("/attacker")
def attacker():
    return render_template("attacker.html")

# ===== PHONE (DRONE CAMERA SCREEN) =====
@app.route("/phone")
def phone():
    return render_template("phone.html")


def resolve_attacker_location(latitude=None, longitude=None, ip_address=None):
    if latitude is not None and longitude is not None:
        try:
            lat = float(latitude)
            lon = float(longitude)
        except (TypeError, ValueError):
            lat = None
            lon = None
        if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
            if 19.00 <= lat <= 19.30 and 72.70 <= lon <= 73.10:
                location = "Mumbai, India"
            elif 28.60 <= lat <= 28.90 and 77.10 <= lon <= 77.40:
                location = "New Delhi, India"
            elif 18.50 <= lat <= 19.80 and 72.20 <= lon <= 73.50:
                location = "Western India"
            else:
                location = "External network origin"
            return {"lat": lat, "lon": lon, "location": location}

    if ip_address:
        return {"lat": None, "lon": None, "location": f"Remote IP: {ip_address}"}

    base_lat, base_lon = generate_location()
    return {"lat": base_lat, "lon": base_lon, "location": "Unverified network origin"}


# ===== ATTACK TRIGGER =====
@app.route("/attack", methods=["GET", "POST"])
def attack():
    global attack_detected, attack_time, phone_alert, attacker_lat, attacker_lon, attacker_location, attacker_ip

    payload = request.get_json(silent=True) or {}
    if request.method == "POST":
        latitude = payload.get("lat")
        longitude = payload.get("lon")
        if latitude is not None and longitude is not None:
            position = resolve_attacker_location(latitude, longitude, request.remote_addr)
            attacker_lat = position["lat"]
            attacker_lon = position["lon"]
            attacker_location = position["location"]
            attacker_ip = request.remote_addr
        else:
            attacker_ip = request.remote_addr or request.access_route[0] if request.access_route else None
            attacker_location = f"Remote IP: {attacker_ip}" if attacker_ip else "Unknown network origin"
            attacker_lat = None
            attacker_lon = None

    attack_detected = True
    attack_time = time.time()
    phone_alert = "DANGER"
    log = AttackLog(
        timestamp=attack_time,
        status="Attack Triggered",
        device="Unknown Device",
        signal=None,
        location=attacker_location,
        lat=attacker_lat,
        lon=attacker_lon,
        action="Attack started",
        fake_data=None,
        phone=phone_alert
    )
    db.session.add(log)
    db.session.commit()
    if request.method == "POST":
        return jsonify({"status": "Attack received", "location": attacker_location,
                        "lat": attacker_lat, "lon": attacker_lon})
    return render_template("attacker.html")

# ===== GENERATE LOCATION (SIMULATED TRACKING) =====
def generate_location():
    base_lat = 21.1458
    base_lon = 79.0882
    return base_lat, base_lon

# ===== STATUS API =====
@app.route("/status")
def status():
    global attack_detected, attack_time, phone_alert, attacker_lat, attacker_lon, attacker_location

    if attack_detected:
        elapsed = time.time() - attack_time

        if elapsed >= 3:
            phone_alert = "DEFENSE"

        if elapsed >= 5:
            if attacker_lat is not None and attacker_lon is not None:
                lat = attacker_lat
                lon = attacker_lon
                location = attacker_location
            else:
                lat, lon = generate_location()
                location = "Unverified network origin"

            log = AttackLog(
                timestamp=time.time(),
                status="🚨 SPYWARE ATTACK DETECTED",
                device="Unknown Device",
                signal="-42 dBm",
                location=location,
                lat=lat,
                lon=lon,
                action="Fake data deployed",
                fake_data="Decoy credentials sent",
                phone=phone_alert
            )
            db.session.add(log)
            db.session.commit()
            return jsonify({
                "status": "🚨 SPYWARE ATTACK DETECTED",
                "device": "Unknown Device",
                "signal": "-42 dBm",
                "location": location,
                "lat": lat,
                "lon": lon,
                "action": "Fake data deployed",
                "fake_data": "Decoy credentials sent",
                "phone": phone_alert
            })

        current_location = attacker_location if attacker_location and attacker_location != "Unknown location" else "Tracking..."
        return jsonify({
            "status": "⚠️ Suspicious Activity...",
            "device": "Scanning...",
            "signal": "-",
            "location": current_location,
            "lat": attacker_lat,
            "lon": attacker_lon,
            "action": "Analyzing...",
            "fake_data": "-",
            "phone": phone_alert
        })

    return jsonify({
        "status": "🟢 Monitoring...",
        "device": "-",
        "signal": "-",
        "location": "-",
        "lat": None,
        "lon": None,
        "action": "System Secure",
        "fake_data": "-",
        "phone": "SAFE"
    })

# ===== LOGS API =====
@app.route("/api/logs")
def get_logs():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(50).all()
    return jsonify([{
        "id": log.id,
        "timestamp": log.timestamp,
        "status": log.status,
        "device": log.device,
        "signal": log.signal,
        "location": log.location,
        "lat": log.lat,
        "lon": log.lon,
        "action": log.action,
        "fake_data": log.fake_data,
        "phone": log.phone
    } for log in logs])

# ===== RESET (OPTIONAL FOR DEMO) =====
@app.route("/reset", methods=["GET", "POST"])
def reset():
    global attack_detected, attack_time, phone_alert, attacker_lat, attacker_lon, attacker_location, attacker_ip
    attack_detected = False
    attack_time = None
    phone_alert = "SAFE"
    attacker_lat = None
    attacker_lon = None
    attacker_location = "Unknown location"
    attacker_ip = None
    AttackLog.query.delete()
    db.session.commit()
    return "System Reset"

# ===== DEEPFAKE DASHBOARD =====
@app.route("/deepfake")
def deepfake():
    return render_template("deepfake.html")

# ===== DEEPFAKE ANALYSIS API =====
@app.route("/api/analyze", methods=["POST"])
def analyze_media():
    if 'file' not in request.files:
        return jsonify({"error": "No media file provided."}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file."}), 400
        
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    time.sleep(2.5) # Simulate processing time

    is_fake = random.choice([True, True, False]) # Bias towards finding fakes
    base_confidence = random.uniform(85.0, 99.9) if is_fake else random.uniform(90.0, 99.9)
    
    spectral_distortion = random.uniform(40.0, 98.0) if is_fake else random.uniform(5.0, 25.0)
    facial_artifacts = random.uniform(50.0, 95.0) if is_fake else random.uniform(2.0, 15.0)
    temporal_consistency = random.uniform(10.0, 45.0) if is_fake else random.uniform(80.0, 99.0)
    
    result = {
        "status": "success",
        "filename": filename,
        "is_deepfake": is_fake,
        "confidence": round(base_confidence, 2),
        "metrics": {
            "spectral_distortion": round(spectral_distortion, 1),
            "facial_artifacts": round(facial_artifacts, 1),
            "temporal_consistency": round(temporal_consistency, 1)
        },
        "message": "CRITICAL MANIPULATION DETECTED" if is_fake else "VERIFIED AUTHENTIC/NO TAMPERING"
    }

    # Log deepfake attempt into PhantomGuard system tracking database!
    log = AttackLog(
        timestamp=time.time(),
        status="Deepfake Scan Executed",
        device="Scanner Upload",
        signal="-",
        location="-",
        lat=None,
        lon=None,
        action=f"Scanned {filename}: {'FAKE' if is_fake else 'REAL'}",
        fake_data=str(round(base_confidence, 2)) + "% Conf",
        phone="SAFE"
    )
    db.session.add(log)
    db.session.commit()

    return jsonify(result)

# ===== RUN SERVER =====
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")