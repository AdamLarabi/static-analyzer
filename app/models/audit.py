"""
app/models/audit.py — Modèle AuditLog.
Trace toutes les actions sensibles : login, création/suppression de tickets,
gestion d'utilisateurs, génération PDF, etc.
"""

from datetime import datetime, timezone
from app.extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username   = db.Column(db.String(64), nullable=False)   # snapshot au moment de l'action
    action     = db.Column(db.String(64), nullable=False, index=True)
    target     = db.Column(db.String(256), nullable=True)   # ex: "ticket#42", "user:alice"
    ip_address = db.Column(db.String(45), nullable=True)    # IPv4 ou IPv6
    details    = db.Column(db.Text, nullable=True)          # JSON ou description libre
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    actor = db.relationship("User", backref="audit_logs", foreign_keys=[user_id])

    def __repr__(self):
        return f"<AuditLog {self.action} by {self.username}>"


# ── Actions prédéfinies ────────────────────────────────────────────────────────

class AuditAction:
    LOGIN              = "login"
    LOGOUT             = "logout"
    LOGIN_FAILED       = "login_failed"
    TICKET_CREATE      = "ticket_create"
    TICKET_DELETE      = "ticket_delete"
    TICKET_NOTE        = "ticket_note"
    TICKET_TAG         = "ticket_tag"
    USER_CREATE        = "user_create"
    USER_DELETE        = "user_delete"
    USER_TOGGLE        = "user_toggle_active"
    USER_PERM          = "user_permission"
    USER_RESET_PWD     = "user_reset_password"
    PDF_GENERATE       = "pdf_generate"
    TOTP_ENABLE        = "totp_enable"
    TOTP_DISABLE       = "totp_disable"
    YARA_UPLOAD        = "yara_rule_upload"
    YARA_TOGGLE        = "yara_rule_toggle"
    YARA_DELETE        = "yara_rule_delete"
    BATCH_ANALYSIS     = "batch_analysis"
