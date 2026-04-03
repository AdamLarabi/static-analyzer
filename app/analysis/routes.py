"""
app/analysis/routes.py — Routes d'analyse de fichiers.
Sécurité : validation extension + magic bytes, nettoyage du nom,
           fichier temporaire supprimé après analyse.
"""

import os
import uuid
import tempfile
import logging
from werkzeug.utils import secure_filename

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, current_app, jsonify)
from flask_login import login_required, current_user

from app.extensions import limiter
from app.analysis.engine import run_full_analysis, detect_file_type

logger = logging.getLogger(__name__)

analysis_bp = Blueprint("analysis", __name__)

# Extensions autorisées (doit correspondre à config)
ALLOWED_EXTENSIONS = {
    "exe", "dll", "sys", "bin", "dat",
    "pdf",
    "docx", "doc", "xls", "xlsx",
    "png", "jpg", "jpeg", "gif", "bmp",
    "zip", "rar", "7z",
    "js", "vbs", "ps1", "bat", "cmd",
    "elf", "so",
}


def _allowed_file(filename: str) -> bool:
    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ── Upload page ───────────────────────────────────────────────────────────────

@analysis_bp.route("/")
@login_required
def upload():
    return render_template("analysis/upload.html")


# ── Analyze ───────────────────────────────────────────────────────────────────

@analysis_bp.route("/analyze", methods=["POST"])
@login_required
@limiter.limit("20 per hour")   # Max 20 analyses/heure par IP
def analyze():
    """
    Reçoit le fichier, valide, analyse, retourne le rapport.
    Le fichier n'est JAMAIS stocké de façon permanente — supprimé après analyse.
    """
    if "file" not in request.files:
        flash("Aucun fichier reçu.", "danger")
        return redirect(url_for("analysis.upload"))

    file = request.files["file"]

    if not file.filename:
        flash("Nom de fichier vide.", "danger")
        return redirect(url_for("analysis.upload"))

    # Nettoyage du nom de fichier (évite path traversal)
    filename = secure_filename(file.filename)
    if not filename:
        flash("Nom de fichier invalide.", "danger")
        return redirect(url_for("analysis.upload"))

    # Vérification extension
    if not _allowed_file(filename):
        flash(
            f"Extension non supportée. "
            f"Extensions autorisées : {', '.join(sorted(ALLOWED_EXTENSIONS))}",
            "danger"
        )
        return redirect(url_for("analysis.upload"))

    # Vérification taille (backup — Flask vérifie MAX_CONTENT_LENGTH)
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > current_app.config["MAX_CONTENT_LENGTH"]:
        flash("Fichier trop volumineux (max 50 Mo).", "danger")
        return redirect(url_for("analysis.upload"))

    # Sauvegarde temporaire avec nom aléatoire (évite les conflits)
    tmp_dir  = tempfile.mkdtemp()
    tmp_name = f"{uuid.uuid4().hex}_{filename}"
    tmp_path = os.path.join(tmp_dir, tmp_name)

    try:
        file.save(tmp_path)

        # Double vérification du type via magic bytes
        detected_type = detect_file_type(tmp_path, filename)
        logger.info(
            "Analyse démarrée: user=%s file=%s type=%s size=%d",
            current_user.username, filename, detected_type, size
        )

        result = run_full_analysis(tmp_path, filename)

    except Exception as e:
        logger.error("Erreur analyse %s: %s", filename, str(e))
        flash(f"Erreur lors de l'analyse : {str(e)}", "danger")
        return redirect(url_for("analysis.upload"))

    finally:
        # Nettoyage garanti même en cas d'exception
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        if os.path.exists(tmp_dir):
            os.rmdir(tmp_dir)

    return render_template(
        "analysis/report.html",
        data=result,
        can_save=current_user.has_permission("save_ticket"),
        can_pdf=current_user.has_permission("generate_pdf"),
    )


# ── VT check AJAX ─────────────────────────────────────────────────────────────

@analysis_bp.route("/vt-check/<sha256>")
@login_required
def vt_check(sha256: str):
    """
    Endpoint AJAX pour interroger VirusTotal depuis le rapport.
    Retourne les stats en JSON.
    """
    # Validation du hash (64 chars hex)
    if not sha256 or len(sha256) != 64 or not all(c in "0123456789abcdefABCDEF" for c in sha256):
        return jsonify({"error": "Hash invalide"}), 400

    from app.analysis.engine import check_virustotal
    result = check_virustotal(sha256.lower())

    vt_url = f"https://www.virustotal.com/gui/file/{sha256.lower()}"

    if isinstance(result, dict):
        return jsonify({"stats": result, "vt_url": vt_url})
    return jsonify({"message": result, "vt_url": vt_url})