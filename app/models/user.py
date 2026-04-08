"""
app/models/user.py — Modèle utilisateur.
Gère l'authentification, les rôles et les permissions granulaires.
"""

import json
import secrets
from enum import Enum as PyEnum
from datetime import datetime, timezone

import pyotp
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db, login_manager


class Role(str, PyEnum):
    ADMIN   = "admin"
    ANALYST = "analyst"


class User(UserMixin, db.Model):
    """
    Table des utilisateurs.

    permissions : JSON stocké en texte, ex :
        {"save_ticket": true, "generate_pdf": false}
    Seul l'admin peut modifier les permissions d'un analyste.
    Un admin a toutes les permissions par défaut.
    """

    __tablename__ = "users"

    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(64),  unique=True, nullable=False, index=True)
    email        = db.Column(db.String(128), unique=True, nullable=False)
    password_hash= db.Column(db.String(256), nullable=False)
    role         = db.Column(db.Enum(Role),  nullable=False, default=Role.ANALYST)
    is_active    = db.Column(db.Boolean,     nullable=False, default=True)
    _permissions = db.Column("permissions",  db.Text, nullable=False,
                             default='{"save_ticket": false, "generate_pdf": false}')
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login   = db.Column(db.DateTime, nullable=True)

    # ── 2FA TOTP ──────────────────────────────────────────────────────────────
    totp_secret      = db.Column(db.String(64),  nullable=True)   # Secret TOTP (base32)
    totp_enabled     = db.Column(db.Boolean,     nullable=False, default=False)
    totp_backup_codes= db.Column(db.Text,        nullable=True)   # JSON list of hashed backup codes

    # Relation avec les tickets
    tickets = db.relationship("Ticket", backref="owner", lazy="dynamic",
                               cascade="all, delete-orphan")

    # ── Mot de passe ──────────────────────────────────────────────────────────

    def set_password(self, password: str) -> None:
        """Hash le mot de passe avec bcrypt (via Werkzeug)."""
        if len(password) < 8:
            raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256:600000")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # ── Permissions ───────────────────────────────────────────────────────────

    @property
    def permissions(self) -> dict:
        try:
            return json.loads(self._permissions)
        except (json.JSONDecodeError, TypeError):
            return {}

    @permissions.setter
    def permissions(self, value: dict) -> None:
        self._permissions = json.dumps(value)

    def has_permission(self, perm: str) -> bool:
        """
        L'admin a toujours toutes les permissions.
        L'analyste dépend de son JSON de permissions.
        """
        if self.role == Role.ADMIN:
            return True
        return bool(self.permissions.get(perm, False))

    def set_permission(self, perm: str, value: bool) -> None:
        perms = self.permissions
        perms[perm] = value
        self.permissions = perms

    # ── 2FA TOTP helpers ──────────────────────────────────────────────────────

    def generate_totp_secret(self) -> str:
        """Génère un nouveau secret TOTP et le stocke (sans activer le 2FA)."""
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def get_totp_uri(self) -> str:
        """Retourne l'URI TOTP pour générer le QR code."""
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.username,
            issuer_name="DataProtect Analyzer"
        )

    def verify_totp(self, code: str) -> bool:
        """Vérifie un code TOTP (fenêtre ±1 période de 30s pour les décalages d'horloge)."""
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code, valid_window=1)

    BACKUP_CODE_LENGTH = 8  # hex chars per backup code (token_hex(4))

    def generate_backup_codes(self) -> list[str]:
        """Génère 8 codes de secours à usage unique, les hache et les stocke."""
        codes = [secrets.token_hex(self.BACKUP_CODE_LENGTH // 2).upper() for _ in range(8)]
        hashed = [generate_password_hash(c) for c in codes]
        self.totp_backup_codes = json.dumps(hashed)
        return codes  # Retourne les codes en clair (affichage unique)

    def use_backup_code(self, code: str) -> bool:
        """Consomme un code de secours. Retourne True si valide."""
        if not self.totp_backup_codes:
            return False
        try:
            hashed_list = json.loads(self.totp_backup_codes)
        except (json.JSONDecodeError, TypeError):
            return False
        for i, h in enumerate(hashed_list):
            if check_password_hash(h, code.upper().strip()):
                hashed_list.pop(i)
                self.totp_backup_codes = json.dumps(hashed_list)
                return True
        return False

    def disable_totp(self) -> None:
        """Désactive le 2FA et efface toutes les données TOTP."""
        self.totp_enabled      = False
        self.totp_secret       = None
        self.totp_backup_codes = None

    # ── Role helpers ──────────────────────────────────────────────────────────

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    @property
    def is_analyst(self) -> bool:
        return self.role == Role.ANALYST

    # ── Flask-Login ───────────────────────────────────────────────────────────

    def get_id(self) -> str:
        return str(self.id)

    def __repr__(self) -> str:
        return f"<User {self.username} [{self.role}]>"


# ── Loader Flask-Login ────────────────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id: str):
    """Charge l'utilisateur depuis la BDD à chaque requête authentifiée."""
    return db.session.get(User, int(user_id))