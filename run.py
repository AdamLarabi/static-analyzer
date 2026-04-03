#!/usr/bin/env python3
"""
run.py — Point d'entrée de l'application Static Analyzer.
Lance le serveur Flask via la factory create_app().
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    # En production, Gunicorn ou uWSGI prend le relais.
    # Ce bloc sert uniquement au développement local.
    app.run(host="0.0.0.0", port=5000, debug=False)