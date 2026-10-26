import os
import re
import json
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse
from pathlib import Path

from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from security.phishing_detector import analyze_text_rules
from security.url_analyzer import analyze_url
from security.risk_assessment import combine_assessment
from ai.gemma_client import analyze_with_gemma, chat_with_gemma, model_status

load_dotenv()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change-this-for-production")
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
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                input_preview TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                category TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)


def save_scan(scan_type, input_preview, result):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO scans (created_at, scan_type, input_preview, risk_level, category, result_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    scan_type,
                    input_preview[:240],
                    result.get("risk_level", "Inconclusive"),
                    result.get("category", "General analysis"),
                    json.dumps(result, ensure_ascii=False),
                ),
            )
    except sqlite3.Error:
        app.logger.exception("Could not save scan history")


def image_extension_ok(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


@app.route("/")
def index():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'High'").fetchone()[0]
        recent = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("index.html", total=total, high=high, recent=recent, model=model_status())


@app.route("/analyze", methods=["POST"])
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
def history():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("history.html", scans=rows)


@app.route("/history/clear", methods=["POST"])
def clear_history():
    with get_db() as conn:
        conn.execute("DELETE FROM scans")
    return jsonify({"ok": True})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model": model_status()})


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
