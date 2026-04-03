"""
app/models/__init__.py — Expose tous les modèles.
SQLAlchemy a besoin que les modèles soient importés
avant db.create_all() pour créer les tables.
"""

from app.models.user   import User, Role
from app.models.ticket import Ticket, TicketNote

__all__ = ["User", "Role", "Ticket", "TicketNote"]