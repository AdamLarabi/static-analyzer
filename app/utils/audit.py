"""
app/utils/audit.py — Helper pour écrire dans l'audit log.
Usage : log_action(AuditAction.TICKET_CREATE, target="ticket#42", details="...")
"""

from flask import request
from flask_login import current_user

from app.extensions import db
from app.models.audit import AuditLog


def log_action(action: str, target: str = None, details: str = None,
               user=None, username: str = None) -> None:
    """
    Enregistre une action dans l'audit log.
    Si user/username non fournis, utilise current_user.
    """
    try:
        actor    = user or (current_user if current_user.is_authenticated else None)
        uid      = actor.id       if actor else None
        uname    = username or (actor.username if actor else "anonymous")
        ip       = request.remote_addr if request else None

        entry = AuditLog(
            user_id    = uid,
            username   = uname,
            action     = action,
            target     = target,
            ip_address = ip,
            details    = details,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        # Ne jamais planter l'app à cause d'un log raté
        db.session.rollback()
