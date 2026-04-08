"""
app/extensions.py — Instances des extensions Flask.
Initialisées ici sans app, puis liées via init_app() dans create_app().
Ce pattern évite les imports circulaires entre modules.
"""

import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate

# ORM base de données
db = SQLAlchemy()

# Migrations de schéma (Alembic)
migrate = Migrate()

# Gestionnaire d'authentification
login_manager = LoginManager()
login_manager.login_view       = "auth.login"
login_manager.login_message    = "Veuillez vous connecter pour accéder à cette page."
login_manager.login_message_category = "warning"

# Rate limiting — Redis si REDIS_URL défini, sinon mémoire (dev)
_redis_url = os.environ.get("REDIS_URL", "")
_storage   = _redis_url if _redis_url else "memory://"

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=_storage,
)

# Protection CSRF sur tous les formulaires POST
csrf = CSRFProtect()