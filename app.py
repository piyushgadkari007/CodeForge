
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import time
import random
import os
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('PHANTOMGUARD_SECRET', 'phantomguard-demo-key')
app.config['GOOGLE_MAPS_API_KEY'] = os.environ.get('GOOGLE_MAPS_API_KEY', '')
# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phantomguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
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

# ===== HOME (DEFENDER DASHBOARD) =====
@app.route("/")
def home():
    user = User.query.get(session['user_id']) if session.get('user_id') else None
    return render_template("index.html", user=user, google_maps_api_key=app.config['GOOGLE_MAPS_API_KEY'])


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
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
            return redirect(url_for("home"))
    return render_template("auth.html", mode="signup")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            next_path = request.args.get("next") or request.form.get("next") or url_for("home")
            if not next_path.startswith('/') or next_path.startswith('//'):
                next_path = url_for("home")
            return redirect(next_path)
        flash("Email or password is incorrect.", "error")
    return render_template("auth.html", mode="login")


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

# ===== ATTACK TRIGGER =====
@app.route("/attack")
def attack():
    global attack_detected, attack_time, phone_alert
    attack_detected = True
    attack_time = time.time()
    phone_alert = "DANGER"
    # Log the attack in the database
    log = AttackLog(
        timestamp=attack_time,
        status="Attack Triggered",
        device="Unknown Device",
        signal=None,
        location=None,
        lat=None,
        lon=None,
        action="Attack started",
        fake_data=None,
        phone=phone_alert
    )
    db.session.add(log)
    db.session.commit()
    return render_template("attacker.html")

# ===== GENERATE LOCATION (SIMULATED TRACKING) =====
def generate_location():
    base_lat = 21.1458
    base_lon = 79.0882
    return base_lat, base_lon

# ===== STATUS API =====
@app.route("/status")
def status():
    global attack_detected, attack_time, phone_alert


    if attack_detected:
        elapsed = time.time() - attack_time

        # After 2-3 sec → show defense on phone
        if elapsed >= 3:
            phone_alert = "DEFENSE"

        # After 5 sec → full detection on laptop
        if elapsed >= 5:
            lat, lon = generate_location()
            # Log detection in the database
            log = AttackLog(
                timestamp=time.time(),
                status="🚨 SPYWARE ATTACK DETECTED",
                device="Unknown Device",
                signal="-42 dBm",
                location="Same Network",
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
                "location": "Same Network",
                "lat": lat,
                "lon": lon,
                "action": "Fake data deployed",
                "fake_data": "Decoy credentials sent",
                "phone": phone_alert
            })

        # During attack but before full detection
        return jsonify({
            "status": "⚠️ Suspicious Activity...",
            "device": "Scanning...",
            "signal": "-",
            "location": "-",
            "lat": None,
            "lon": None,
            "action": "Analyzing...",
            "fake_data": "-",
            "phone": phone_alert
        })

    # Normal state
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
    global attack_detected, attack_time, phone_alert
    attack_detected = False
    attack_time = None
    phone_alert = "SAFE"
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
if __name__ == "__main__":
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0")