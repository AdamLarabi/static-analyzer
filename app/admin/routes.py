"""
app/admin/routes.py — Interface d'administration.
Toutes les routes sont protégées par @admin_required.
"""

import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, abort, jsonify)
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from app.extensions import db
from app.models.user import User, Role
from app.models.ticket import Ticket

logger = logging.getLogger(__name__)
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ── Décorateur admin ──────────────────────────────────────────────────────────

def admin_required(f):
    """Protège une route — admin uniquement."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Dashboard ─────────────────────────────────────────────────────────────────

@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    """Vue globale : stats, alertes critiques, activité récente."""
    now       = datetime.now(timezone.utc)
    month_ago = now - timedelta(days=30)

    # Statistiques générales
    total_users    = User.query.count()
    total_analysts = User.query.filter_by(role=Role.ANALYST).count()
    total_tickets  = Ticket.query.count()
    tickets_month  = Ticket.query.filter(Ticket.created_at >= month_ago).count()

    # Distribution des niveaux de menace
    threat_dist = {
        "CRITICAL": Ticket.query.filter_by(threat_level="CRITICAL").count(),
        "HIGH":     Ticket.query.filter_by(threat_level="HIGH").count(),
        "MEDIUM":   Ticket.query.filter_by(threat_level="MEDIUM").count(),
        "LOW":      Ticket.query.filter_by(threat_level="LOW").count(),
    }

    # Alertes : tickets critiques récents (score >= 75)
    from flask import current_app
    threshold = current_app.config.get("ALERT_SCORE_THRESHOLD", 75)
    alerts = (Ticket.query
              .filter(Ticket.threat_score >= threshold)
              .order_by(Ticket.created_at.desc())
              .limit(10)
              .all())

    # Activité récente (tous tickets)
    recent_tickets = (Ticket.query
                      .order_by(Ticket.created_at.desc())
                      .limit(15)
                      .all())

    # Top YARA rules déclenchées
    yara_counter = {}
    for ticket in Ticket.query.all():
        for match in ticket.result.get("yara_matches", []):
            rule = match.get("rule", "")
            if rule and rule != "YARA_ERROR":
                yara_counter[rule] = yara_counter.get(rule, 0) + 1
    top_yara = sorted(yara_counter.items(), key=lambda x: x[1], reverse=True)[:8]

    # Activité par utilisateur
    user_activity = []
    for user in User.query.filter_by(role=Role.ANALYST).all():
        count = Ticket.query.filter_by(user_id=user.id).count()
        last  = (Ticket.query.filter_by(user_id=user.id)
                 .order_by(Ticket.created_at.desc())
                 .first())
        user_activity.append({
            "user":         user,
            "ticket_count": count,
            "last_analysis": last.created_at if last else None,
        })

    return render_template("admin/dashboard.html",
        total_users    = total_users,
        total_analysts = total_analysts,
        total_tickets  = total_tickets,
        tickets_month  = tickets_month,
        threat_dist    = threat_dist,
        alerts         = alerts,
        alert_threshold= threshold,
        recent_tickets = recent_tickets,
        top_yara       = top_yara,
        user_activity  = user_activity,
    )


# ── Gestion des utilisateurs ──────────────────────────────────────────────────

@admin_bp.route("/users")
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=all_users)


@admin_bp.route("/users/create", methods=["POST"])
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    email    = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", "analyst")

    # Validations
    if not username or not email or not password:
        flash("Tous les champs sont requis.", "danger")
        return redirect(url_for("admin.users"))

    if len(password) < 8:
        flash("Le mot de passe doit contenir au moins 8 caractères.", "danger")
        return redirect(url_for("admin.users"))

    if User.query.filter_by(username=username).first():
        flash(f"Nom d'utilisateur '{username}' déjà utilisé.", "danger")
        return redirect(url_for("admin.users"))

    if User.query.filter_by(email=email).first():
        flash(f"Email '{email}' déjà utilisé.", "danger")
        return redirect(url_for("admin.users"))

    try:
        user_role = Role(role)
    except ValueError:
        user_role = Role.ANALYST

    user = User(
        username  = username,
        email     = email,
        role      = user_role,
        is_active = True,
        permissions = {"save_ticket": False, "generate_pdf": False},
    )
    try:
        user.set_password(password)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("admin.users"))

    db.session.add(user)
    db.session.commit()

    logger.info("Utilisateur créé: %s [%s] par admin %s", username, role, current_user.username)
    flash(f"Utilisateur '{username}' créé avec succès.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_user_active(user_id: int):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        return jsonify({"error": "Impossible de désactiver son propre compte"}), 400

    user.is_active = not user.is_active
    db.session.commit()

    status = "activé" if user.is_active else "désactivé"
    logger.info("Compte %s %s par %s", user.username, status, current_user.username)
    return jsonify({"active": user.is_active, "status": status})


@admin_bp.route("/users/<int:user_id>/permissions", methods=["POST"])
@admin_required
def update_permissions(user_id: int):
    """Met à jour les permissions d'un utilisateur."""
    user = User.query.get_or_404(user_id)

    if user.is_admin:
        return jsonify({"error": "Les admins ont toutes les permissions par défaut"}), 400

    data = request.get_json(silent=True) or {}
    perm = data.get("permission")
    val  = data.get("value")

    if perm not in ("save_ticket", "generate_pdf") or not isinstance(val, bool):
        return jsonify({"error": "Paramètres invalides"}), 400

    user.set_permission(perm, val)
    db.session.commit()

    logger.info(
        "Permission %s=%s pour %s par admin %s",
        perm, val, user.username, current_user.username
    )
    return jsonify({"success": True, "permission": perm, "value": val})


@admin_bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_password(user_id: int):
    user     = User.query.get_or_404(user_id)
    password = request.form.get("new_password", "")

    if len(password) < 8:
        flash("Le mot de passe doit contenir au moins 8 caractères.", "danger")
        return redirect(url_for("admin.users"))

    try:
        user.set_password(password)
        db.session.commit()
        flash(f"Mot de passe de '{user.username}' réinitialisé.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id: int):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("Impossible de supprimer son propre compte.", "danger")
        return redirect(url_for("admin.users"))

    username = user.username
    db.session.delete(user)
    db.session.commit()

    logger.info("Utilisateur %s supprimé par %s", username, current_user.username)
    flash(f"Utilisateur '{username}' supprimé.", "info")
    return redirect(url_for("admin.users"))


# ── Alertes ───────────────────────────────────────────────────────────────────

@admin_bp.route("/alerts")
@admin_required
def alerts():
    """Vue dédiée aux analyses à score critique."""
    from flask import current_app
    threshold = current_app.config.get("ALERT_SCORE_THRESHOLD", 75)
    alerts = (Ticket.query
              .filter(Ticket.threat_score >= threshold)
              .order_by(Ticket.created_at.desc())
              .all())
    return render_template("admin/alerts.html",
                           alerts=alerts,
                           threshold=threshold)