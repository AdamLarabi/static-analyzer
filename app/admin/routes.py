"""
app/admin/routes.py — Interface d'administration.
Toutes les routes sont protégées par @admin_required.
"""

import logging
import re
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, abort, jsonify)
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from werkzeug.utils import secure_filename

import yara
from sqlalchemy import func

from app.extensions import db
from app.models.user import User, Role
from app.models.ticket import Ticket
from app.models.audit import AuditAction, AuditLog
from app.models.yara_rule import YaraRule
from app.utils.audit import log_action
from app.analysis.yara_engine import YARA_RULES_SOURCE

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

    # Activité par utilisateur (single query with aggregation)
    rows = (db.session.query(
                User,
                func.count(Ticket.id).label("ticket_count"),
                func.max(Ticket.created_at).label("last_analysis"),
            )
            .outerjoin(Ticket, Ticket.user_id == User.id)
            .filter(User.role == Role.ANALYST)
            .group_by(User.id)
            .all())
    user_activity = [
        {"user": u, "ticket_count": cnt, "last_analysis": last}
        for u, cnt, last in rows
    ]

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

    log_action(AuditAction.USER_CREATE, target=f"user:{username}", details=f"role={role}")
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
    log_action(AuditAction.USER_TOGGLE, target=f"user:{user.username}", details=status)
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

    log_action(AuditAction.USER_PERM, target=f"user:{user.username}", details=f"{perm}={val}")
    logger.info("Permission %s=%s pour %s par admin %s", perm, val, user.username, current_user.username)
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
        log_action(AuditAction.USER_RESET_PWD, target=f"user:{user.username}")
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
    log_action(AuditAction.USER_DELETE, target=f"user:{username}")
    db.session.delete(user)
    db.session.commit()

    logger.info("Utilisateur %s supprimé par %s", username, current_user.username)
    flash(f"Utilisateur '{username}' supprimé.", "info")
    return redirect(url_for("admin.users"))


# ── YARA Rules Manager ───────────────────────────────────────────────────────

@admin_bp.route("/yara")
@admin_required
def yara_rules():
    """Liste des règles YARA — built-in + custom."""
    builtin_names = re.findall(r'rule\s+(\w+)', YARA_RULES_SOURCE)

    custom_rules = YaraRule.query.order_by(YaraRule.created_at.desc()).all()
    return render_template("admin/yara.html",
                           builtin_names=builtin_names,
                           custom_rules=custom_rules)


@admin_bp.route("/yara/upload", methods=["POST"])
@admin_required
def yara_upload():
    """Upload et valide une règle YARA custom."""
    name    = request.form.get("name", "").strip()
    desc    = request.form.get("description", "").strip()[:256]
    severity= request.form.get("severity", "medium")
    source  = ""

    # Source via textarea ou fichier uploadé
    if "rule_file" in request.files and request.files["rule_file"].filename:
        f = request.files["rule_file"]
        if not secure_filename(f.filename).endswith(".yar"):
            flash("Seuls les fichiers .yar sont acceptés.", "danger")
            return redirect(url_for("admin.yara_rules"))
        try:
            source = f.read().decode("utf-8")
        except UnicodeDecodeError:
            flash("Le fichier doit être encodé en UTF-8.", "danger")
            return redirect(url_for("admin.yara_rules"))
    else:
        source = request.form.get("source", "").strip()

    if not name:
        flash("Le nom de la règle est requis.", "danger")
        return redirect(url_for("admin.yara_rules"))

    if not source:
        flash("Le contenu de la règle est requis.", "danger")
        return redirect(url_for("admin.yara_rules"))

    if severity not in ("critical", "high", "medium", "low"):
        severity = "medium"

    # Vérifier unicité du nom
    if YaraRule.query.filter_by(name=name).first():
        flash(f"Une règle nommée '{name}' existe déjà.", "danger")
        return redirect(url_for("admin.yara_rules"))

    # Validation syntaxique YARA — erreur claire si invalide
    try:
        yara.compile(source=source)
    except yara.SyntaxError as e:
        flash(f"Erreur de syntaxe YARA : {e}", "danger")
        return redirect(url_for("admin.yara_rules"))
    except Exception as e:
        flash(f"Erreur de compilation YARA : {e}", "danger")
        return redirect(url_for("admin.yara_rules"))

    rule = YaraRule(
        name        = name,
        description = desc,
        source      = source,
        severity    = severity,
        is_active   = True,
        uploaded_by = current_user.id,
    )
    db.session.add(rule)
    db.session.commit()

    log_action(AuditAction.YARA_UPLOAD, target=f"yara:{name}")
    logger.info("Règle YARA '%s' uploadée par %s", name, current_user.username)
    flash(f"Règle '{name}' ajoutée avec succès.", "success")
    return redirect(url_for("admin.yara_rules"))


@admin_bp.route("/yara/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def yara_toggle(rule_id: int):
    """Active ou désactive une règle YARA custom."""
    rule = YaraRule.query.get_or_404(rule_id)
    rule.is_active = not rule.is_active
    db.session.commit()

    log_action(AuditAction.YARA_TOGGLE, target=f"yara:{rule.name}",
               details="active" if rule.is_active else "disabled")
    return jsonify({"active": rule.is_active, "name": rule.name})


@admin_bp.route("/yara/<int:rule_id>/delete", methods=["POST"])
@admin_required
def yara_delete(rule_id: int):
    """Supprime une règle YARA custom."""
    rule = YaraRule.query.get_or_404(rule_id)
    name = rule.name
    log_action(AuditAction.YARA_DELETE, target=f"yara:{name}")
    db.session.delete(rule)
    db.session.commit()
    flash(f"Règle '{name}' supprimée.", "info")
    return redirect(url_for("admin.yara_rules"))


@admin_bp.route("/yara/<int:rule_id>/source")
@admin_required
def yara_source(rule_id: int):
    """Retourne le source d'une règle custom en JSON (pour l'affichage modal)."""
    rule = YaraRule.query.get_or_404(rule_id)
    return jsonify({"name": rule.name, "source": rule.source, "description": rule.description})


# ── Audit Log ────────────────────────────────────────────────────────────────

@admin_bp.route("/audit")
@admin_required
def audit_log():
    """Journal d'audit — toutes les actions sensibles."""
    page        = request.args.get("page", 1, type=int)
    action_filter = request.args.get("action", "")
    user_filter   = request.args.get("user", "")

    query = AuditLog.query.order_by(AuditLog.created_at.desc())
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    if user_filter:
        query = query.filter(AuditLog.username.ilike(f"%{user_filter}%"))

    logs        = query.paginate(page=page, per_page=50, error_out=False)
    all_actions = db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    all_actions = [a[0] for a in all_actions]

    return render_template("admin/audit.html",
                           logs=logs,
                           all_actions=all_actions,
                           action_filter=action_filter,
                           user_filter=user_filter)


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