"""
app/__init__.py — Factory de l'application Flask.
Pattern Application Factory : permet de créer plusieurs instances
(tests, dev, prod) avec des configurations différentes.
"""

import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

from flask import Flask

from app.config import config_map
from app.extensions import db, migrate, login_manager, limiter, csrf


def create_app(env: str = None) -> Flask:
    """
    Crée et configure l'instance Flask.
    env : 'development' | 'production' | None (utilise FLASK_ENV ou 'default')
    """
    if env is None:
        env = os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__)
    app.config.from_object(config_map[env])

    # ── Dossiers nécessaires ──────────────────────────────────────────────────
    _ensure_dirs(app)

    # ── Extensions ───────────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    # ── Blueprints ───────────────────────────────────────────────────────────
    _register_blueprints(app)

    # ── Context Processor ───────────────────────────────────────────────────
    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow()}

    # ── Création des tables (si elles n'existent pas) ─────────────────────────
    with app.app_context():
        from app.models import user, ticket, audit, yara_rule  # noqa: F401 — enregistre les modèles
        db.create_all()
        _create_default_admin(app)

    # ── Logging ──────────────────────────────────────────────────────────────
    _configure_logging(app)

    # ── Headers de sécurité HTTP ─────────────────────────────────────────────
    _register_security_headers(app)

    return app


# ─────────────────────────────────────────────────────────────────────────────

def _ensure_dirs(app: Flask) -> None:
    """Crée les dossiers requis s'ils n'existent pas."""
    dirs = [
        app.config["UPLOAD_FOLDER"],
        app.config["PDF_LOGO_FOLDER"],
        os.path.join(os.path.dirname(app.root_path), "logs"),
        os.path.join(os.path.dirname(app.root_path), "database"),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def _register_blueprints(app: Flask) -> None:
    """Enregistre tous les blueprints de l'application."""
    from app.auth.routes     import auth_bp
    from app.analysis.routes import analysis_bp
    from app.tickets.routes  import tickets_bp
    from app.admin.routes    import admin_bp
    from app.pdf.routes      import pdf_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(tickets_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(pdf_bp)


def _create_default_admin(app: Flask) -> None:
    """
    Crée un compte admin par défaut au premier lancement.
    Le mot de passe DOIT être changé immédiatement après installation.
    """
    from app.models.user import User, Role

    if User.query.filter_by(username="admin").first():
        return  # Déjà existant

    default_password = os.environ.get("ADMIN_DEFAULT_PASSWORD", "ChangeMe!2024")
    admin = User(
        username    = "admin",
        email       = "admin@local",
        role        = Role.ADMIN,
        is_active   = True,
        permissions = {"save_ticket": True, "generate_pdf": True},
    )
    admin.set_password(default_password)
    db.session.add(admin)
    db.session.commit()
    app.logger.warning(
        "Compte admin par défaut créé. "
        "Changez le mot de passe immédiatement via /admin/users."
    )


def _configure_logging(app: Flask) -> None:
    """Configure les logs rotatifs en fichier + console."""
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    )

    # Handler fichier (5 Mo, 5 rotations)
    try:
        file_handler = RotatingFileHandler(
            app.config["LOG_FILE"], maxBytes=5_242_880, backupCount=5
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        app.logger.addHandler(file_handler)
    except OSError:
        pass  # Si le dossier logs n'est pas accessible

    # Handler console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    app.logger.addHandler(console_handler)

    app.logger.setLevel(log_level)


def _register_security_headers(app: Flask) -> None:
    """Ajoute les headers de sécurité HTTP sur chaque réponse."""

    @app.after_request
    def set_security_headers(response):
        # Empêche le navigateur de deviner le type MIME
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Protège contre le clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Désactive l'XSS auditor legacy (remplacé par CSP)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Referrer minimal
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Content Security Policy — ajuste selon tes besoins (fonts Google autorisées)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response