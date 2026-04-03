# Static Analyzer v2.0 — Guide d'installation

## Prérequis système (Ubuntu/Debian)

```bash
# Dépendances système pour WeasyPrint et python-magic
sudo apt update
sudo apt install -y \
    python3-pip python3-venv \
    libpango-1.0-0 libpangoft2-1.0-0 \
    libcairo2 libgdk-pixbuf2.0-0 \
    libffi-dev libxml2-dev libxslt1-dev \
    file libmagic1 \
    libgirepository1.0-dev gir1.2-pango-1.0

# Créer l'utilisateur dédié (ne pas faire tourner en root)
sudo useradd -r -s /bin/false analyzer
```

## Installation

```bash
# Cloner / copier les fichiers dans /opt/static-analyzer
sudo mkdir -p /opt/static-analyzer
sudo chown analyzer:analyzer /opt/static-analyzer

# Passer en utilisateur analyzer
sudo -u analyzer bash

cd /opt/static-analyzer

# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Créer les dossiers nécessaires
mkdir -p database logs uploads app/static/uploads/logos
```

## Configuration

Éditer le fichier service `/etc/systemd/system/static-analyzer.service` :
- Remplacer `SECRET_KEY` par une clé aléatoire forte : `python3 -c "import secrets; print(secrets.token_hex(32))"`
- Renseigner `VT_API_KEY` avec votre clé VirusTotal
- Changer `ADMIN_DEFAULT_PASSWORD`

## Déploiement

```bash
# Copier le service
sudo cp static-analyzer.service /etc/systemd/system/

# Activer et démarrer
sudo systemctl daemon-reload
sudo systemctl enable static-analyzer
sudo systemctl start static-analyzer

# Vérifier
sudo systemctl status static-analyzer
sudo journalctl -u static-analyzer -f
```

## Premier démarrage

1. Aller sur http://<IP>:5000
2. Se connecter avec admin / le mot de passe défini dans ADMIN_DEFAULT_PASSWORD
3. Aller dans Admin → Utilisateurs → Créer les analystes
4. Assigner les permissions (save_ticket, generate_pdf) par utilisateur

## Structure des fichiers clés

```
/opt/static-analyzer/
├── run.py                    ← Point d'entrée
├── requirements.txt
├── static-analyzer.service
├── app/
│   ├── config.py             ← Configuration
│   ├── models/               ← BDD (User, Ticket)
│   ├── analysis/             ← Moteur d'analyse
│   ├── auth/                 ← Authentification
│   ├── tickets/              ← Gestion tickets
│   ├── admin/                ← Interface admin
│   ├── pdf/                  ← Génération PDF
│   └── templates/            ← HTML Jinja2
├── database/
│   └── analyzer.db           ← SQLite (auto-créé)
└── logs/
    ├── analyzer.log
    ├── access.log
    └── error.log
```

## Notes de sécurité

- Ne jamais committer les clés dans le code source
- Utiliser un reverse proxy (Nginx) en production pour HTTPS
- Le compte admin par défaut doit être changé immédiatement
- Les fichiers analysés sont supprimés après analyse (jamais stockés)