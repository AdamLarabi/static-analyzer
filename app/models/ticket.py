"""
app/models/ticket.py — Modèle ticket d'analyse sauvegardée.
Un ticket = une analyse complète persistée en BDD avec ses métadonnées.
"""

import json
from datetime import datetime, timezone

from app.extensions import db


class Ticket(db.Model):
    """
    Représente une analyse malware sauvegardée.

    result_json : stocke le dictionnaire complet du rapport d'analyse,
                  permettant de ré-afficher le rapport sans re-analyser le fichier.
    tags        : liste JSON de strings, ex: ["ransomware", "APT", "confirmed-clean"]
    """

    __tablename__ = "tickets"

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                             nullable=False, index=True)

    # ── Identification du fichier ─────────────────────────────────────────────
    filename     = db.Column(db.String(256), nullable=False)
    sha256       = db.Column(db.String(64),  nullable=False, index=True)
    md5          = db.Column(db.String(32),  nullable=True)
    sha1         = db.Column(db.String(40),  nullable=True)
    file_type    = db.Column(db.String(64),  nullable=True)   # "PE", "PDF", "Image"...

    # ── Score et niveau de menace ─────────────────────────────────────────────
    threat_score = db.Column(db.Integer,     nullable=False, default=0)
    threat_level = db.Column(db.String(16),  nullable=False, default="LOW")
    # LOW | MEDIUM | HIGH | CRITICAL

    # ── Contenu de l'analyse ──────────────────────────────────────────────────
    _result_json = db.Column("result_json", db.Text, nullable=False, default="{}")
    comment      = db.Column(db.Text,       nullable=True)   # Commentaire initial
    _tags        = db.Column("tags",        db.Text, nullable=False, default="[]")

    # ── Métadonnées ───────────────────────────────────────────────────────────
    created_at   = db.Column(db.DateTime,
                             default=lambda: datetime.now(timezone.utc),
                             nullable=False)
    updated_at   = db.Column(db.DateTime,
                             default=lambda: datetime.now(timezone.utc),
                             onupdate=lambda: datetime.now(timezone.utc))

    # Relation avec les notes
    notes = db.relationship("TicketNote", backref="ticket", lazy="dynamic",
                             cascade="all, delete-orphan",
                             order_by="TicketNote.created_at")

    # ── result_json ───────────────────────────────────────────────────────────

    @property
    def result(self) -> dict:
        try:
            return json.loads(self._result_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    @result.setter
    def result(self, value: dict) -> None:
        self._result_json = json.dumps(value, default=str)

    # ── Tags ──────────────────────────────────────────────────────────────────

    @property
    def tags(self) -> list:
        try:
            return json.loads(self._tags)
        except (json.JSONDecodeError, TypeError):
            return []

    @tags.setter
    def tags(self, value: list) -> None:
        # Normalisation : lowercase, strip, dédoublonnage
        clean = list({t.strip().lower() for t in value if t.strip()})
        self._tags = json.dumps(clean)

    def add_tag(self, tag: str) -> None:
        current = self.tags
        tag = tag.strip().lower()
        if tag and tag not in current:
            current.append(tag)
            self.tags = current

    def remove_tag(self, tag: str) -> None:
        self.tags = [t for t in self.tags if t != tag.strip().lower()]

    # ── Helpers ───────────────────────────────────────────────────────────────

    @property
    def is_critical(self) -> bool:
        return self.threat_score >= 75

    @property
    def vt_url(self) -> str:
        """Lien direct vers la page VirusTotal du fichier."""
        return f"https://www.virustotal.com/gui/file/{self.sha256}"

    def __repr__(self) -> str:
        return f"<Ticket #{self.id} {self.filename} score={self.threat_score}>"


class TicketNote(db.Model):
    """
    Notes/commentaires additionnels ajoutés sur un ticket après sa création.
    Un analyste peut enrichir son ticket avec des observations au fil du temps.
    """

    __tablename__ = "ticket_notes"

    id         = db.Column(db.Integer, primary_key=True)
    ticket_id  = db.Column(db.Integer, db.ForeignKey("tickets.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                           nullable=True)
    content    = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime,
                           default=lambda: datetime.now(timezone.utc),
                           nullable=False)

    author = db.relationship("User", backref="notes")

    def __repr__(self) -> str:
        return f"<TicketNote ticket={self.ticket_id} by user={self.user_id}>"