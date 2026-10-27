import os
import re
import json
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse
from pathlib import Path

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv

from security.phishing_detector import analyze_text_rules
from security.url_analyzer import analyze_url
from security.risk_assessment import combine_assessment
from ai.gemma_client import analyze_with_gemma, chat_with_gemma, model_status

load_dotenv()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY") or os.urandom(32).hex()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "false").lower() == "true"
DB_PATH = Path(os.getenv("DATABASE_PATH", "database/cybershield.db"))
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                input_preview TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                category TEXT NOT NULL,
                result_json TEXT NOT NULL,
                user_id INTEGER
            )
        """)
        # Upgrade databases created by an older version without deleting history.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "user_id" not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.path in ("/analyze", "/chat", "/history/clear"):
                return jsonify({"error": "Please log in to continue.", "login_required": True}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def save_scan(scan_type, input_preview, result):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO scans (created_at, scan_type, input_preview, risk_level, category, result_json, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    scan_type,
                    input_preview[:240],
                    result.get("risk_level", "Inconclusive"),
                    result.get("category", "General analysis"),
                    json.dumps(result, ensure_ascii=False),
                    session.get("user_id"),
                ),
            )
    except sqlite3.Error:
        app.logger.exception("Could not save scan history")


def image_extension_ok(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            flash("Username must be 3–30 characters using letters, numbers, dots, underscores, or hyphens.", "error")
        elif len(password) < 10:
            flash("Password must be at least 10 characters long.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            try:
                with get_db() as conn:
                    cur = conn.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)", (username, generate_password_hash(password), datetime.now(timezone.utc).isoformat(timespec="seconds")))
                    session.clear()
                    session["user_id"] = cur.lastrowid
                    session["username"] = username
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("That username is already registered. Please choose another.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("index"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (session["user_id"],)).fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND risk_level = 'High'", (session["user_id"],)).fetchone()[0]
        recent = conn.execute("SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 5", (session["user_id"],)).fetchall()
    return render_template("index.html", total=total, high=high, recent=recent, model=model_status())


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    text_input = (request.form.get("message") or "").strip()
    url_input = (request.form.get("url") or "").strip()
    image = request.files.get("image")
    has_image = image and image.filename

    if not text_input and not url_input and not has_image:
        return jsonify({"error": "Enter a message, URL, or upload an image to analyze."}), 400
    if len(text_input) > 12000:
        return jsonify({"error": "Text is too long. Please keep it under 12,000 characters."}), 400
    if url_input and len(url_input) > 2048:
        return jsonify({"error": "URL is too long."}), 400

    rule_result = analyze_text_rules(text_input) if text_input else {
        "risk_level": "Low", "category": "No message text supplied", "indicators": [], "explanation": "No message text was supplied to the rule-based checker."
    }
    url_result = analyze_url(url_input) if url_input else None
    image_note = None
    ai_result = None

    try:
        if has_image:
            if not image_extension_ok(image.filename):
                return jsonify({"error": "Unsupported image type. Use PNG, JPG, JPEG, or WEBP."}), 400
            # Keep image in memory; do not save the uploaded image to disk.
            from PIL import Image
            import io
            raw = image.read()
            if len(raw) > 5 * 1024 * 1024:
                return jsonify({"error": "Image must be 5 MB or smaller."}), 400
            img = Image.open(io.BytesIO(raw)).convert("RGB")
            ai_result = analyze_with_gemma(text_input, url_input, image=img)
            image_note = "Image analyzed in memory; the uploaded file was not stored."
        elif text_input or url_input:
            ai_result = analyze_with_gemma(text_input, url_input)
    except Exception as exc:
        app.logger.warning("Gemma analysis unavailable: %s", exc)
        ai_result = None
        image_note = "AI analysis was unavailable; the result below uses local rule-based checks only."

    result = combine_assessment(rule_result, url_result, ai_result)
    result["image_note"] = image_note
    result["ai_enabled"] = bool(ai_result)
    result["url_checks"] = url_result
    preview = text_input or url_input or "Uploaded image"
    save_scan("image + text" if has_image and text_input else "image" if has_image else "URL" if url_input and not text_input else "text", preview, result)
    return jsonify(result)


@app.route("/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Please enter a question."}), 400
    if len(message) > 4000:
        return jsonify({"error": "Please keep your question under 4,000 characters."}), 400
    try:
        answer = chat_with_gemma(message)
        return jsonify({"answer": answer, "ai_enabled": True})
    except Exception:
        return jsonify({
            "answer": "The AI assistant is currently unavailable. General safety tip: do not share passwords or OTPs, avoid unexpected links, and verify requests through the service's official app or website.",
            "ai_enabled": False
        })


@app.route("/history")
@login_required
def history():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 100", (session["user_id"],)).fetchall()
    return render_template("history.html", scans=rows)


@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    with get_db() as conn:
        conn.execute("DELETE FROM scans WHERE user_id = ?", (session["user_id"],))
    return jsonify({"ok": True})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model": model_status()})


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
