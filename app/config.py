"""
app/config.py — Configuration centralisée.
Toutes les valeurs sensibles DOIVENT être surchargées via variables d'environnement
en production. Ne jamais committer de clés réelles.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load variables from .env if it exists
load_dotenv()


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class Config:
    # ── Sécurité Flask ────────────────────────────────────────────────────────
    # Génère une clé aléatoire forte au démarrage si la variable n'est pas définie.
    # En production, définir SECRET_KEY dans l'environnement système.
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32)

    # ── Base de données ───────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or \
        "sqlite:///" + os.path.join(BASE_DIR, "database", "analyzer.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Sessions ──────────────────────────────────────────────────────────────
    SESSION_COOKIE_HTTPONLY  = True   # Inaccessible depuis JS
    SESSION_COOKIE_SAMESITE  = "Lax"  # Protège contre CSRF basique
    SESSION_COOKIE_SECURE    = os.environ.get("HTTPS", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # ── Upload ────────────────────────────────────────────────────────────────
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 Mo max par fichier
    UPLOAD_FOLDER      = os.path.join(BASE_DIR, "uploads")

    ALLOWED_EXTENSIONS = {
        "exe", "dll", "sys", "bin", "dat",   # PE / binaires Windows
        "msi", "jar", "lnk",                  # Installateurs et raccourcis
        "pdf",                                 # Documents PDF
        "docx", "doc", "xls", "xlsx",         # Office
        "png", "jpg", "jpeg", "gif", "bmp",   # Images
        "zip", "rar", "7z", "iso", "img",     # Archives et images disque
        "js", "vbs", "ps1", "bat", "cmd",     # Scripts Windows
        "py", "php", "sh",                     # Scripts Web/Linux
        "elf", "so",                           # Binaires Linux
        "apk",                                 # Android
        "vhd", "vhdx",                         # Disques virtuels
    }

    # ── VirusTotal ────────────────────────────────────────────────────────────
    VT_API_KEY = os.environ.get("VT_API_KEY", "REMPLACER_PAR_CLE_REELLE")
    VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
    VT_GUI_URL  = "https://www.virustotal.com/gui/file"

    # ── Scoring — seuil d'alerte admin ───────────────────────────────────────
    ALERT_SCORE_THRESHOLD = 75   # Score >= 75 → apparaît dans les alertes admin

    # ── PDF ───────────────────────────────────────────────────────────────────
    PDF_LOGO_FOLDER = os.path.join(BASE_DIR, "app", "static", "uploads", "logos")

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_FILE  = os.path.join(BASE_DIR, "logs", "analyzer.log")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    # En production, forcer HTTPS + cookie sécurisé
    SESSION_COOKIE_SECURE = True


# Mapping utilisé dans create_app()
config_map = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "default":     DevelopmentConfig,
}