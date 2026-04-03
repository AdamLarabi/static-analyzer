"""
app/extensions.py — Instances des extensions Flask.
Initialisées ici sans app, puis liées via init_app() dans create_app().
Ce pattern évite les imports circulaires entre modules.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

# ORM base de données
db = SQLAlchemy()

# Gestionnaire d'authentification
login_manager = LoginManager()
login_manager.login_view       = "auth.login"          # Redirige si non connecté
login_manager.login_message    = "Veuillez vous connecter pour accéder à cette page."
login_manager.login_message_category = "warning"

# Rate limiting — protège les routes sensibles (login, upload)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],           # Pas de limite globale, appliqué par route
    storage_uri="memory://",     # En prod, utiliser Redis : "redis://localhost:6379"
)

# Protection CSRF sur tous les formulaires POST
csrf = CSRFProtect()