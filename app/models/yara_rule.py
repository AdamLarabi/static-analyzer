"""
app/models/yara_rule.py — Règles YARA personnalisées uploadées par l'admin.
Les règles built-in (dans yara_engine.py) ne sont pas en BDD.
"""

from datetime import datetime, timezone
from app.extensions import db


class YaraRule(db.Model):
    __tablename__ = "yara_rules"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(128), unique=True, nullable=False, index=True)
    description = db.Column(db.String(256), nullable=True)
    source      = db.Column(db.Text, nullable=False)   # Contenu .yar complet
    severity    = db.Column(db.String(16), nullable=False, default="medium")
    is_active   = db.Column(db.Boolean, nullable=False, default=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    author = db.relationship("User", backref="yara_rules", foreign_keys=[uploaded_by])

    def __repr__(self):
        return f"<YaraRule {self.name} active={self.is_active}>"
