"""
app/analysis/routes.py — Routes d'analyse de fichiers.
Sécurité : validation extension + magic bytes, nettoyage du nom,
           fichier temporaire supprimé après analyse.
Supporte l'analyse unitaire ET l'analyse en masse (jusqu'à 20 fichiers).
"""

import contextlib
import os
import uuid
import tempfile
import logging
import shutil
from werkzeug.utils import secure_filename

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, jsonify)
from flask_login import login_required, current_user

from app.extensions import limiter
from app.analysis.engine import run_full_analysis, detect_file_type
from app.config import Config

logger = logging.getLogger(__name__)

analysis_bp = Blueprint("analysis", __name__)

MAX_BATCH_FILES = 20


@contextlib.contextmanager
def _temp_dir():
    """Context manager that creates a temp directory and removes it on exit."""
    d = tempfile.mkdtemp()
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _validate_file(file) -> tuple[bool, str]:
    """Valide un fichier uploadé. Retourne (ok, nom_sécurisé_ou_erreur)."""
    if not file or not file.filename:
        return False, "Fichier vide ou sans nom."
    filename = secure_filename(file.filename)
    if not filename:
        return False, "Nom de fichier invalide."
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in Config.ALLOWED_EXTENSIONS:
        return False, f"Extension non supportée : {filename}"
    return True, filename


# ── Upload page ───────────────────────────────────────────────────────────────

@analysis_bp.route("/")
@login_required
def upload():
    return render_template("analysis/upload.html")


# ── Analyze (unitaire) ────────────────────────────────────────────────────────

@analysis_bp.route("/analyze", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def analyze():
    """Analyse un seul fichier et retourne le rapport détaillé."""
    if "file" not in request.files:
        flash("Aucun fichier reçu.", "danger")
        return redirect(url_for("analysis.upload"))

    file = request.files["file"]
    ok, filename = _validate_file(file)
    if not ok:
        flash(filename, "danger")
        return redirect(url_for("analysis.upload"))

    try:
        with _temp_dir() as tmp_dir:
            tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4().hex}_{filename}")
            file.save(tmp_path)
            detected_type = detect_file_type(tmp_path, filename)
            logger.info("Analyse: user=%s file=%s type=%s", current_user.username, filename, detected_type)
            result = run_full_analysis(tmp_path, filename)
    except Exception as e:
        logger.error("Erreur analyse %s: %s", filename, str(e))
        flash(f"Erreur lors de l'analyse : {str(e)}", "danger")
        return redirect(url_for("analysis.upload"))

    return render_template(
        "analysis/report.html",
        data=result,
        can_save=current_user.has_permission("save_ticket"),
        can_pdf=current_user.has_permission("generate_pdf"),
    )


# ── Analyze en masse ──────────────────────────────────────────────────────────

@analysis_bp.route("/analyze-batch", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def analyze_batch():
    """
    Analyse plusieurs fichiers en une seule requête (max 20).
    Retourne une page récapitulative avec le score de chaque fichier.
    """
    files = request.files.getlist("files")

    if not files or all(not f.filename for f in files):
        flash("Aucun fichier reçu.", "danger")
        return redirect(url_for("analysis.upload"))

    if len(files) > MAX_BATCH_FILES:
        flash(f"Maximum {MAX_BATCH_FILES} fichiers à la fois.", "danger")
        return redirect(url_for("analysis.upload"))

    results = []
    errors  = []

    with _temp_dir() as tmp_dir:
        for file in files:
            ok, filename = _validate_file(file)
            if not ok:
                errors.append({"filename": file.filename or "?", "error": filename})
                continue

            tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4().hex}_{filename}")
            try:
                file.save(tmp_path)
                result = run_full_analysis(tmp_path, filename)
                results.append(result)
                logger.info("Batch: user=%s file=%s score=%s",
                            current_user.username, filename,
                            result.get("threat_score", {}).get("score", "?"))
            except Exception as e:
                logger.error("Batch erreur %s: %s", filename, str(e))
                errors.append({"filename": filename, "error": str(e)})

    if not results and errors:
        for err in errors:
            flash(f"{err['filename']} : {err['error']}", "danger")
        return redirect(url_for("analysis.upload"))

    return render_template(
        "analysis/batch_report.html",
        results=results,
        errors=errors,
        can_save=current_user.has_permission("save_ticket"),
        can_pdf=current_user.has_permission("generate_pdf"),
    )


# ── VT check AJAX ─────────────────────────────────────────────────────────────

@analysis_bp.route("/vt-check/<sha256>")
@login_required
def vt_check(sha256: str):
    """Endpoint AJAX pour interroger VirusTotal depuis le rapport."""
    if not sha256 or len(sha256) != 64 or not all(c in "0123456789abcdefABCDEF" for c in sha256):
        return jsonify({"error": "Hash invalide"}), 400

    from app.analysis.engine import check_virustotal
    result = check_virustotal(sha256.lower())
    vt_url = f"https://www.virustotal.com/gui/file/{sha256.lower()}"

    if isinstance(result, dict):
        return jsonify({"stats": result, "vt_url": vt_url})
    return jsonify({"message": result, "vt_url": vt_url})