"""
app/auth/forms.py — Formulaires d'authentification avec validation WTForms.
La validation côté serveur est obligatoire, ne jamais faire confiance au client.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp


class LoginForm(FlaskForm):
    """Formulaire de connexion."""

    username = StringField(
        "Nom d'utilisateur",
        validators=[
            DataRequired(message="Le nom d'utilisateur est requis."),
            Length(min=3, max=64, message="Entre 3 et 64 caractères."),
            # Autorise uniquement les caractères alphanumériques et _.-
            Regexp(r"^[\w.\-]+$", message="Caractères non autorisés."),
        ],
        render_kw={"autocomplete": "username", "placeholder": "username"},
    )

    password = PasswordField(
        "Mot de passe",
        validators=[
            DataRequired(message="Le mot de passe est requis."),
            Length(min=8, max=128, message="Entre 8 et 128 caractères."),
        ],
        render_kw={"autocomplete": "current-password", "placeholder": "••••••••"},
    )

    remember = BooleanField("Rester connecté")
    submit   = SubmitField("Se connecter")