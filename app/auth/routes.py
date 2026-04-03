"""
app/auth/routes.py — Routes d'authentification.
Sécurité : rate limiting sur /login, messages d'erreur génériques,
log des tentatives échouées, mise à jour de last_login.
"""

from datetime import datetime, timezone

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db, limiter
from app.models.user import User
from app.auth.forms import LoginForm

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")   # Max 10 tentatives/minute par IP
def login():
    """
    Page de connexion.
    Redirige vers le dashboard approprié si déjà connecté.
    """
    if current_user.is_authenticated:
        return _redirect_after_login(current_user)

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()

        # Message volontairement générique : ne révèle pas si le user existe
        if not user or not user.check_password(form.password.data):
            # Log de la tentative échouée (sans révéler l'info)
            import logging
            logging.getLogger(__name__).warning(
                "Tentative de connexion échouée pour username='%s' depuis IP=%s",
                form.username.data, request.remote_addr
            )
            flash("Identifiants incorrects.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.is_active:
            flash("Compte désactivé. Contactez un administrateur.", "danger")
            return render_template("auth/login.html", form=form)

        # Connexion réussie
        login_user(user, remember=form.remember.data)
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        # Redirection sécurisée (évite les open redirects)
        next_page = request.args.get("next")
        if next_page and _is_safe_redirect(next_page):
            return redirect(next_page)
        return _redirect_after_login(user)

    return render_template("auth/login.html", form=form)


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("auth.login"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _redirect_after_login(user: User):
    """Redirige vers le bon dashboard selon le rôle."""
    if user.is_admin:
        return redirect(url_for("admin.dashboard"))
    return redirect(url_for("analysis.upload"))


def _is_safe_redirect(url: str) -> bool:
    """
    Vérifie que l'URL de redirection est interne (commence par /).
    Protège contre les open redirects.
    """
    return url.startswith("/") and not url.startswith("//")