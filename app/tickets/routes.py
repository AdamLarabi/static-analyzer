"""
app/tickets/routes.py — Gestion des tickets d'analyse sauvegardés.
"""

import logging
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, abort, jsonify)
from flask_login import login_required, current_user

from app.extensions import db
from app.models.ticket import Ticket, TicketNote

logger = logging.getLogger(__name__)
tickets_bp = Blueprint("tickets", __name__, url_prefix="/tickets")

# Tags prédéfinis suggérés
SUGGESTED_TAGS = [
    "ransomware", "apt", "trojan", "spyware", "keylogger",
    "confirmed-clean", "false-positive", "c2", "dropper",
    "persistence", "lateral-movement", "under-investigation",
]


# ── Liste des tickets ─────────────────────────────────────────────────────────

@tickets_bp.route("/")
@login_required
def list_tickets():
    """
    Admin : voit tous les tickets.
    Analyste : voit seulement les siens.
    """
    query = Ticket.query.order_by(Ticket.created_at.desc())
    if not current_user.is_admin:
        query = query.filter_by(user_id=current_user.id)

    tickets = query.all()
    return render_template("tickets/list.html",
                           tickets=tickets,
                           suggested_tags=SUGGESTED_TAGS)


# ── Créer un ticket depuis un rapport ─────────────────────────────────────────

@tickets_bp.route("/save", methods=["POST"])
@login_required
def save_ticket():
    """
    Sauvegarde un rapport d'analyse en ticket.
    Accessible uniquement si permission save_ticket = True.
    """
    if not current_user.has_permission("save_ticket"):
        abort(403)

    import json
    data    = request.get_json(silent=True) or {}
    result  = data.get("result")
    comment = data.get("comment", "").strip()[:1000]
    tags    = data.get("tags", [])

    if not result or not isinstance(result, dict):
        return jsonify({"error": "Données d'analyse manquantes"}), 400

    hashes = result.get("hashes", {})
    sha256 = hashes.get("sha256", "")

    if not sha256:
        return jsonify({"error": "SHA256 manquant dans le rapport"}), 400

    # Vérifier si ce hash existe déjà pour cet user (évite les doublons)
    existing = Ticket.query.filter_by(
        user_id=current_user.id, sha256=sha256
    ).first()
    if existing:
        return jsonify({
            "warning": "Un ticket existe déjà pour ce fichier.",
            "ticket_id": existing.id,
            "redirect": url_for("tickets.ticket_detail", ticket_id=existing.id),
        })

    threat = result.get("threat_score", {})
    ticket = Ticket(
        user_id      = current_user.id,
        filename     = result.get("filename", "unknown"),
        sha256       = sha256,
        md5          = hashes.get("md5", ""),
        sha1         = hashes.get("sha1", ""),
        file_type    = result.get("file_type", "UNKNOWN"),
        threat_score = threat.get("score", 0),
        threat_level = threat.get("level", "LOW"),
        comment      = comment,
    )
    ticket.result = result
    ticket.tags   = tags

    db.session.add(ticket)
    db.session.commit()

    logger.info("Ticket #%d créé par %s pour %s", ticket.id, current_user.username, sha256[:16])
    return jsonify({
        "success": True,
        "ticket_id": ticket.id,
        "redirect": url_for("tickets.ticket_detail", ticket_id=ticket.id),
    })


# ── Détail d'un ticket ────────────────────────────────────────────────────────

@tickets_bp.route("/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id: int):
    ticket = _get_ticket_or_403(ticket_id)
    notes  = ticket.notes.all()
    return render_template("tickets/detail.html",
                           ticket=ticket,
                           notes=notes,
                           data=ticket.result,
                           suggested_tags=SUGGESTED_TAGS,
                           can_pdf=current_user.has_permission("generate_pdf"))


# ── Ajouter une note ──────────────────────────────────────────────────────────

@tickets_bp.route("/<int:ticket_id>/notes", methods=["POST"])
@login_required
def add_note(ticket_id: int):
    ticket  = _get_ticket_or_403(ticket_id)
    content = request.form.get("content", "").strip()

    if not content:
        flash("La note ne peut pas être vide.", "warning")
        return redirect(url_for("tickets.ticket_detail", ticket_id=ticket_id))

    if len(content) > 2000:
        flash("Note trop longue (max 2000 caractères).", "warning")
        return redirect(url_for("tickets.ticket_detail", ticket_id=ticket_id))

    note = TicketNote(
        ticket_id = ticket.id,
        user_id   = current_user.id,
        content   = content,
    )
    db.session.add(note)
    db.session.commit()
    flash("Note ajoutée.", "success")
    return redirect(url_for("tickets.ticket_detail", ticket_id=ticket_id))


# ── Modifier les tags ─────────────────────────────────────────────────────────

@tickets_bp.route("/<int:ticket_id>/tags", methods=["POST"])
@login_required
def update_tags(ticket_id: int):
    ticket = _get_ticket_or_403(ticket_id)
    tags   = request.get_json(silent=True) or {}
    new_tags = tags.get("tags", [])

    if not isinstance(new_tags, list):
        return jsonify({"error": "Format invalide"}), 400

    # Max 10 tags, max 30 chars chacun
    new_tags = [t[:30] for t in new_tags if isinstance(t, str)][:10]
    ticket.tags = new_tags
    db.session.commit()

    return jsonify({"success": True, "tags": ticket.tags})


@tickets_bp.route("/<int:ticket_id>/rename", methods=["POST"])
@login_required
def rename_ticket(ticket_id: int):
    ticket = _get_ticket_or_403(ticket_id)
    data   = request.get_json(silent=True) or {}
    new_name = data.get("name", "").strip()[:100]

    if not new_name:
        return jsonify({"error": "Le nom ne peut pas être vide"}), 400

    ticket.filename = new_name
    db.session.commit()
    return jsonify({"success": True, "new_name": ticket.filename})


# ── Supprimer un ticket ───────────────────────────────────────────────────────

@tickets_bp.route("/<int:ticket_id>/delete", methods=["POST"])
@login_required
def delete_ticket(ticket_id: int):
    ticket = _get_ticket_or_403(ticket_id)
    db.session.delete(ticket)
    db.session.commit()
    flash("Ticket supprimé.", "info")
    return redirect(url_for("tickets.list_tickets"))


# ── Helper ────────────────────────────────────────────────────────────────────

def _get_ticket_or_403(ticket_id: int) -> Ticket:
    """Récupère un ticket. Vérifie que l'user y a accès."""
    ticket = Ticket.query.get_or_404(ticket_id)
    if not current_user.is_admin and ticket.user_id != current_user.id:
        abort(403)
    return ticket