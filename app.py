"""Phase 4: Flask SOC Analyst Web Portal for Project 07: Phishing Triage."""
from __future__ import annotations

import os
import secrets
import uuid
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional; environment variables still work
    def load_dotenv(*_a, **_k):
        return False
from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from triage.pipeline import PhishingTriagePipeline
from triage.report_generator import generate_pdf_report_bytes, render_html_report

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = {".eml", ".msg"}
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = Flask(__name__)
# No hard-coded default secret: use FLASK_SECRET_KEY from .env, or a random key per start.
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


@app.errorhandler(413)
def too_large(_err):
    flash("File too large. The limit is 25 MB.", "danger")
    return redirect(url_for("index"))


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp
pipeline = PhishingTriagePipeline(db_path=BASE_DIR / "phishing_triage.db")


@app.route("/", methods=["GET"])
def index():
    history = pipeline.list_analyses()
    stats = {
        "total": len(history),
        "critical_high": sum(1 for item in history if item["risk_score"] >= 50),
        "medium": sum(1 for item in history if 25 <= item["risk_score"] < 50),
        "low": sum(1 for item in history if item["risk_score"] < 25),
    }
    return render_template("index.html", history=history, stats=stats, intel_mode=pipeline.intel.mode)


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("email_file")
    if not uploaded or not uploaded.filename:
        flash("Please choose an .eml or .msg file to analyze.", "warning")
        return redirect(url_for("index"))

    safe_name = secure_filename(uploaded.filename)
    ext = Path(safe_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        flash("Unsupported file type. Upload a .eml or .msg email artifact.", "danger")
        return redirect(url_for("index"))

    # Store under a random name (no overwrites), analyze, then delete the file.
    saved_path = UPLOAD_DIR / f"{uuid.uuid4().hex}{ext}"
    uploaded.save(saved_path)
    try:
        result = pipeline.analyze_file(saved_path)
        # keep the name the analyst uploaded, not the random storage name
        pipeline.rename_source(result["id"], safe_name)
    except Exception as exc:
        flash(f"Failed to parse email artifact: {exc.__class__.__name__}", "danger")
        return redirect(url_for("index"))
    finally:
        saved_path.unlink(missing_ok=True)

    return redirect(url_for("view_analysis", case_id=result["id"]))


@app.route("/analysis/<case_id>", methods=["GET"])
def view_analysis(case_id: str):
    analysis = pipeline.get_analysis(case_id)
    if not analysis:
        flash(f"Case {case_id} was not found.", "warning")
        return redirect(url_for("index"))
    return render_template("analysis_detail.html", analysis=analysis)


@app.route("/api/analysis/<case_id>", methods=["GET"])
def api_get_analysis(case_id: str):
    analysis = pipeline.get_analysis(case_id)
    if not analysis:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(analysis)


@app.route("/analysis/<case_id>/export/html", methods=["GET"])
def export_html(case_id: str):
    analysis = pipeline.get_analysis(case_id)
    if not analysis:
        return "Case not found", 404
    html_content = render_html_report(analysis, BASE_DIR / "templates")
    return Response(
        html_content,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={case_id}_report.html"},
    )


@app.route("/analysis/<case_id>/export/pdf", methods=["GET"])
def export_pdf(case_id: str):
    analysis = pipeline.get_analysis(case_id)
    if not analysis:
        return "Case not found", 404
    pdf_bytes = generate_pdf_report_bytes(analysis)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={case_id}_report.pdf"},
    )


if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=port, debug=debug)
