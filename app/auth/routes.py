"""
app/auth/routes.py — Routes d'authentification + 2FA TOTP.
Flux login : credentials → (si 2FA actif) code TOTP → dashboard
"""

import io
import logging
from datetime import datetime, timezone

import qrcode
import qrcode.image.svg
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, session, send_file, abort)
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db, limiter
from app.models.user import User
from app.models.audit import AuditAction
from app.auth.forms import LoginForm
from app.utils.audit import log_action

logger  = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# Clé de session temporaire — user en attente de validation TOTP
_SESSION_PENDING = "totp_pending_user_id"
_SESSION_REMEMBER= "totp_pending_remember"


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return _redirect_after_login(current_user)

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()

        if not user or not user.check_password(form.password.data):
            logger.warning("Login échoué username='%s' IP=%s", form.username.data, request.remote_addr)
            log_action(AuditAction.LOGIN_FAILED, target=f"user:{form.username.data}",
                       username=form.username.data)
            flash("Identifiants incorrects.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.is_active:
            flash("Compte désactivé. Contactez un administrateur.", "danger")
            return render_template("auth/login.html", form=form)

        # Si 2FA actif → stocker l'user en session et rediriger vers la vérif TOTP
        if user.totp_enabled:
            session[_SESSION_PENDING]  = user.id
            session[_SESSION_REMEMBER] = form.remember.data
            return redirect(url_for("auth.totp_verify"))

        # Pas de 2FA → connexion directe
        _complete_login(user, form.remember.data)
        next_page = request.args.get("next")
        if next_page and _is_safe_redirect(next_page):
            return redirect(next_page)
        return _redirect_after_login(user)

    return render_template("auth/login.html", form=form)


# ── Vérification TOTP (étape 2) ───────────────────────────────────────────────

@auth_bp.route("/2fa/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def totp_verify():
    """Deuxième étape du login : saisir le code TOTP ou un code de secours."""
    user_id = session.get(_SESSION_PENDING)
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user or not user.totp_enabled:
        session.pop(_SESSION_PENDING, None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code    = request.form.get("code", "").strip().replace(" ", "")
        is_backup = len(code) == 8  # codes de secours = 8 chars hex

        if is_backup:
            valid = user.use_backup_code(code)
        else:
            valid = user.verify_totp(code)

        if valid:
            if is_backup:
                db.session.commit()
            remember = session.pop(_SESSION_REMEMBER, False)
            session.pop(_SESSION_PENDING, None)
            _complete_login(user, remember)
            if is_backup:
                log_action(AuditAction.LOGIN, target=f"user:{user.username}",
                           details="via backup code", user=user)
            return _redirect_after_login(user)

        logger.warning("Code TOTP invalide user=%s IP=%s", user.username, request.remote_addr)
        flash("Code invalide. Réessayez.", "danger")

    return render_template("auth/totp_verify.html", username=user.username)


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@login_required
def logout():
    log_action(AuditAction.LOGOUT, target=f"user:{current_user.username}")
    logout_user()
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("auth.login"))


# ── Setup 2FA (admin/analyst via leur profil) ─────────────────────────────────

@auth_bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def totp_setup():
    """Affiche le QR code et confirme l'activation du 2FA."""
    if current_user.totp_enabled:
        flash("Le 2FA est déjà activé.", "info")
        return redirect(url_for("auth.totp_manage"))

    if request.method == "GET":
        # Génère un nouveau secret (non encore activé)
        current_user.generate_totp_secret()
        db.session.commit()

    uri = current_user.get_totp_uri()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if current_user.verify_totp(code):
            backup_codes = current_user.generate_backup_codes()
            current_user.totp_enabled = True
            db.session.commit()
            log_action(AuditAction.TOTP_ENABLE, target=f"user:{current_user.username}")
            logger.info("2FA activé pour %s", current_user.username)
            flash("2FA activé avec succès !", "success")
            return render_template("auth/totp_backup_codes.html", codes=backup_codes)
        flash("Code incorrect. Scannez à nouveau et réessayez.", "danger")

    return render_template("auth/totp_setup.html", totp_uri=uri, username=current_user.username)


@auth_bp.route("/2fa/qrcode.svg")
@login_required
def totp_qrcode():
    """Génère le QR code en SVG pour le template setup."""
    if not current_user.totp_secret:
        abort(404)
    uri = current_user.get_totp_uri()
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="image/svg+xml")


@auth_bp.route("/2fa/manage")
@login_required
def totp_manage():
    """Page de gestion du 2FA (activer / désactiver)."""
    return render_template("auth/totp_manage.html")


@auth_bp.route("/2fa/disable", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def totp_disable():
    """Désactive le 2FA après vérification du mot de passe."""
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        flash("Mot de passe incorrect.", "danger")
        return redirect(url_for("auth.totp_manage"))

    current_user.disable_totp()
    db.session.commit()
    log_action(AuditAction.TOTP_DISABLE, target=f"user:{current_user.username}")
    logger.info("2FA désactivé pour %s", current_user.username)
    flash("2FA désactivé.", "info")
    return redirect(url_for("auth.totp_manage"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _complete_login(user: User, remember: bool) -> None:
    login_user(user, remember=remember)
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    log_action(AuditAction.LOGIN, target=f"user:{user.username}", user=user)


def _redirect_after_login(user: User):
    if user.is_admin:
        return redirect(url_for("admin.dashboard"))
    return redirect(url_for("analysis.upload"))


def _is_safe_redirect(url: str) -> bool:
    return url.startswith("/") and not url.startswith("//")
