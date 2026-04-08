# DataProtect Static Analyzer 
---

## Table des Matières

. [Architecture & Structure](#2-architecture--structure)
. [Authentification & Rôles](#3-authentification--rôles)
. [Upload & Analyse de Fichiers](#4-upload--analyse-de-fichiers)
. [Moteur d'Analyse](#5-moteur-danalyse)
. [Système de Tickets](#6-système-de-tickets)
. [Génération PDF](#7-génération-pdf)
. [Interface Admin](#8-interface-admin)
. [Sécurité Globale](#9-sécurité-globale)
. [Configuration & Déploiement](#10-configuration--déploiement)
. [Dépendances](#11-dépendances)
. [Routes & Endpoints](#12-routes--endpoints)
. [Modèles de Données](#13-modèles-de-données)
. [Points à Améliorer](#14-points-à-améliorer)

---

### Stack Technique

| Couche | Technologie |
|--------|-------------|
| Backend | Flask 3.0.3 (Python 3) |
| Base de données | SQLite (SQLAlchemy ORM) |
| Authentification | Flask-Login + PBKDF2:SHA256 |
| Formulaires / CSRF | Flask-WTF + WTForms |
| Rate Limiting | Flask-Limiter |
| Analyse YARA | yara-python 4.5.1 |
| Parsing PE | pefile 2023.2.7 |
| Détection type fichier | python-magic 0.4.27 |
| Lecture PDF | pypdf 4.3.1 |
| Traitement images | Pillow 10.4.0 |
| Lecture DOCX | python-docx 1.1.2 |
| Génération PDF | WeasyPrint 62.3 |
| VirusTotal | API v3 (requests 2.32.3) |
| Serveur de prod | Gunicorn 22.0.0 |
| Frontend | Jinja2 + CSS personnalisé (thème sombre) |

---

## 2. Architecture & Structure

```
Web App/
│
├── run.py                          → Point d'entrée de l'application
├── requirements.txt                → Dépendances Python
├── .env                            → Variables d'environnement (secrets)
├── .env.example                    → Template de configuration
├── static-analyzer.service         → Service systemd pour la production
│
├── app/
│   ├── __init__.py                 → Factory Flask (create_app)
│   ├── config.py                   → Configuration dev/prod
│   ├── extensions.py               → Initialisation extensions Flask
│   │
│   ├── auth/
│   │   ├── routes.py               → Login / Logout
│   │   └── forms.py                → LoginForm avec validation
│   │
│   ├── analysis/
│   │   ├── routes.py               → Upload + rapport d'analyse
│   │   ├── engine.py               → Orchestrateur principal d'analyse
│   │   ├── yara_engine.py          → 11 règles YARA intégrées
│   │   ├── mitre.py                → Mapping MITRE ATT&CK
│   │   └── suspicious_strings.py   → ~240 mots-clés + regex dynamiques
│   │
│   ├── models/
│   │   ├── user.py                 → Modèle User (rôles + permissions)
│   │   └── ticket.py               → Modèles Ticket + TicketNote
│   │
│   ├── tickets/
│   │   └── routes.py               → Gestion des tickets
│   │
│   ├── admin/
│   │   └── routes.py               → Dashboard admin + gestion utilisateurs
│   │
│   ├── pdf/
│   │   ├── routes.py               → Route génération PDF
│   │   └── generator.py            → Logique de rendu PDF
│   │
│   └── templates/
│       ├── base.html               → Template de base (navbar, style)
│       ├── auth/login.html
│       ├── analysis/upload.html
│       ├── analysis/report.html
│       ├── tickets/list.html
│       ├── tickets/detail.html
│       ├── admin/dashboard.html
│       ├── admin/users.html
│       ├── admin/alerts.html
│       └── pdf/report_pdf.html
│
├── static/uploads/logos/           → Logos clients pour les PDFs
├── uploads/                        → Stockage temporaire des fichiers analysés
├── logs/                           → Logs applicatifs (analyzer, access, error)
└── database/analyzer.db            → Base de données SQLite (auto-créée)
```

---

## 3. Authentification & Rôles

### Rôles Utilisateurs

| Rôle | Accès |
|------|-------|
| **ADMIN** | Accès complet + gestion des utilisateurs |
| **ANALYST** | Analyse de fichiers + tickets (selon permissions) |

### Permissions Granulaires

| Permission | Description |
|------------|-------------|
| `save_ticket` | Sauvegarder les analyses en tickets persistants |
| `generate_pdf` | Générer et télécharger des rapports PDF |

> Les ADMINs ont toutes les permissions par défaut, sans restriction.

### Fonctionnement du Login — `POST /auth/login`

- Formulaire avec token **CSRF** (protection automatique)
- **Rate limiting** : 10 tentatives par minute par IP
- Messages d'erreur **génériques** (ne révèle pas si l'utilisateur existe)
- Mise à jour du champ `last_login` à chaque connexion réussie
- Redirection sécurisée après login (protection contre les open redirects) :
  - Admin → `/admin/dashboard`
  - Analyst → `/analysis/upload`
- Option **"Se souvenir de moi"**
- Logs des tentatives échouées avec l'IP source

### Sécurité des Sessions

| Paramètre | Valeur |
|-----------|--------|
| Durée de vie | 8 heures |
| HttpOnly | Oui (non accessible en JavaScript) |
| SameSite | Lax (protection CSRF) |
| Secure | Oui en production (HTTPS uniquement) |

### Sécurité des Mots de Passe

- Algorithme : **PBKDF2:SHA256** avec **600 000 itérations**
- Minimum **8 caractères** requis (max 128)
- Username : 3–64 caractères, alphanumériques + `._-`

---

## 4. Upload & Analyse de Fichiers

### Route d'Analyse — `POST /analyze`

- **Rate limit :** 20 analyses par heure par IP
- **Taille max :** 50 MB
- **Extensions autorisées :** 50+ types (EXE, DLL, PDF, DOCX, JS, PY, PS1, JPEG, PNG, ZIP, ELF, etc.)

### Étapes de Validation

1. Vérification que le fichier existe et a un nom
2. Extension dans la liste blanche
3. Taille ≤ 50 MB
4. Nom sécurisé via `secure_filename()` + UUID aléatoire
5. Fichier temporaire **supprimé après analyse** (bloc `finally`)

### Flux Complet

```
Utilisateur upload fichier
        ↓
Validation (extension, taille, nom)
        ↓
Sauvegarde temporaire (UUID + extension)
        ↓
run_full_analysis(filepath)
        ↓
Résultat affiché dans report.html
        ↓
Fichier temporaire supprimé
        ↓
Option : Sauvegarder comme ticket / Générer PDF
```

---

## 5. Moteur d'Analyse

Fichier principal : `app/analysis/engine.py` → fonction `run_full_analysis()`

### Étape 1 — Calcul des Hashes

Calcul de **MD5, SHA1, SHA256** pour identification et lookup VirusTotal.

### Étape 2 — Analyse Entropique (Shannon Entropy)

| Entropie | Signification | Score |
|----------|---------------|-------|
| > 7.5 | Binaire probablement chiffré/packé | +30 pts |
| > 7.0 | Suspect | +20 pts |
| > 6.0 | Légèrement suspect | +10 pts |

### Étape 3 — Détection du Type de Fichier

Via **magic bytes** (non basé sur l'extension) :

| Signature | Type détecté |
|-----------|-------------|
| `MZ` | PE (Windows EXE/DLL) |
| `\x7fELF` | ELF (Linux binaire) |
| `%PDF` | PDF |
| `PK\x03\x04` | ZIP-based (DOCX, XLSX, APK…) |
| `\xff\xd8\xff` | JPEG |
| `\x89PNG` | PNG |

> Détection de **type mismatch** : ex. fichier `.jpg` contenant un PE.

### Étape 4 — Extraction de Chaînes

Extraction de toutes les chaînes ASCII imprimables (minimum 4 caractères) → alimentent l'analyse des strings suspectes.

### Étape 5 — Analyse Spécialisée par Type

#### PE (EXE / DLL)
- Liste des **imports DLL** (max 50 entrées : `DLL:fonction`)
- **Timestamp de compilation** (depuis le header PE)
- **Sections** avec nom, taille, entropie

#### PDF
- Extraction des **métadonnées** (auteur, créateur, dates)
- Extraction des **URLs** dans le texte
- Détection de **JavaScript embarqué**
- Détection d'éléments suspects : `/Launch`, `/OpenAction`, `/EmbeddedFile`

#### Images (JPEG, PNG, GIF, BMP)
- Extraction des **métadonnées EXIF**
- Détection de **stéganographie** par analyse entropique
- Recherche de chaînes suspectes (`base64`, `exec`, `eval`, `shell`)

#### Office (DOCX / XLSX)
- Extraction ZIP et détection de **macros VBA**
- Détection d'**URLs externes** dans les relations
- Identification de patterns suspects

#### Scripts (PS1, PY, JS, VBS, SH, BAT)
- Comptage de patterns réseau et d'exécution
- Détection de commandes d'obfuscation

### Étape 6 — Chaînes Suspectes (`suspicious_strings.py`)

**~240 mots-clés** organisés par catégorie + regex dynamiques :

| Catégorie | Exemples |
|-----------|---------|
| Exécution | `cmd.exe`, `powershell`, `wmic`, `rundll32` |
| Download/Staging | `wget`, `curl`, `Invoke-WebRequest`, `DownloadString` |
| Credential Access | `mimikatz`, `procdump`, `comsvcs.dll` |
| Lateral Movement | `psexec`, `net use`, `RDP`, `WinRM` |
| Defense Evasion | `AMSI bypass`, `Set-MpPreference`, `vssadmin` |
| Persistence | `Registry Run keys`, `schtasks`, `AppInit_DLLs` |
| Reconnaissance | `ipconfig`, `whoami`, `systeminfo`, `netstat` |
| Ransomware | `CryptEncrypt`, `bitcoin`, `ransom`, `.locked` |
| Injection | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| C2/Network | `InternetOpenUrl`, `cobalt strike`, `metasploit` |
| Anti-Analysis | `IsDebuggerPresent`, détection VM |
| Keylogger | `SetWindowsHookEx`, `GetAsyncKeyState`, `GetClipboardData` |
| Privilege Escalation | `SeDebugPrivilege`, techniques UAC bypass |

**Regex dynamiques :** PowerShell encodé (base64), IP brutes, chemins UNC (`\\share\`), clés registry, certutil decode, références Tor, suppression shadow copies, etc.

### Étape 7 — Règles YARA (`yara_engine.py`)

11 règles intégrées :

| Règle | MITRE TID | Description |
|-------|-----------|-------------|
| `Ransomware_Indicators` | T1486 | Mots-clés de chiffrement |
| `Shellcode_Indicators` | T1055 | Patterns shellcode courants |
| `Network_Exfil_Indicators` | T1041 | APIs HTTP/socket |
| `Persistence_Mechanisms` | T1547 | Registry/tâches planifiées |
| `Privilege_Escalation` | T1548 | APIs d'élévation |
| `Packer_Indicators` | T1027 | UPX, MPRESS, PECompact |
| `Keylogger_Indicators` | T1056 | APIs hook/surveillance clavier |
| `Anti_Debug_Techniques` | T1622 | Détection de débogueur |
| `Document_Macro_Suspicious` | T1137 | Patterns VBA/macro |
| `PDF_Suspicious` | T1204 | JavaScript/Launch dans PDFs |

Chaque match retourne : nom de la règle, description, sévérité, TID MITRE.

### Étape 8 — Mapping MITRE ATT&CK (`mitre.py`)

Les TIDs des règles YARA sont enrichis avec :
- **Tactique** (Impact, Defense Evasion, Execution, etc.)
- **Nom complet** de la technique
- **Lien officiel** MITRE ATT&CK
- **Description**
- Déduplication des sous-techniques (T1059.001 → T1059)

### Étape 9 — VirusTotal (API v3)

- Lookup par **SHA256** sur l'API VirusTotal v3
- Retourne les stats : `{malicious, suspicious, undetected, harmless}`
- Timeout : 10 secondes
- Gestion gracieuse si `VT_API_KEY` absent

### Étape 10 — Algorithme de Scoring

```
Score de base = 0

Entropie:
  > 7.5 → +30 pts
  > 7.0 → +20 pts
  > 6.0 → +10 pts

YARA matches (par sévérité):
  critical → +40 pts
  high     → +25 pts
  medium   → +10 pts
  low      →  +5 pts

Strings suspectes (par sévérité ÷ 3):
  critical → +13 pts
  + URLs trouvées : min(count × 5, 15) pts
  + Commandes    : min(count × 5, 15) pts

VirusTotal (nombre de détections malveillantes):
  > 20 → +40 pts
  > 10 → +30 pts
  >  5 → +20 pts
  >  0 → +10 pts
  + suspicious : min(count × 2, 10) pts

Score final : clampé entre 0 et 100
```

### Niveaux de Menace

| Score | Niveau | Couleur |
|-------|--------|---------|
| ≥ 75 | **CRITICAL** | Rouge `#ef4444` |
| ≥ 50 | **HIGH** | Orange `#f97316` |
| ≥ 25 | **MEDIUM** | Jaune `#eab308` |
| < 25 | **LOW** | Vert `#22c55e` |

### Structure du Résultat Final

```json
{
  "filename": "malware.exe",
  "file_type": "PE",
  "analysis_time": "2026-04-07 14:30:00 UTC",
  "hashes": { "md5": "...", "sha1": "...", "sha256": "..." },
  "entropy": 7.82,
  "compile_time": "2020-01-15 08:30:00 UTC",
  "imports": ["KERNEL32:VirtualAllocEx", "..."],
  "sections": [{ "name": ".text", "size": 4096, "entropy": 6.5 }],
  "suspicious_strings": {
    "by_category": {
      "execution": [{ "string": "powershell", "severity": "high", "mitre": "T1059.001" }]
    },
    "urls": [...],
    "commands": [...]
  },
  "virustotal": { "malicious": 35, "suspicious": 2, "undetected": 25 },
  "vt_url": "https://www.virustotal.com/gui/file/...",
  "yara_matches": [{ "rule": "Ransomware_Indicators", "severity": "critical" }],
  "mitre_techniques": [{ "id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact" }],
  "threat_score": { "score": 87, "level": "CRITICAL", "color": "#ef4444" }
}
```

---

## 6. Système de Tickets

### Sauvegarder un Ticket — `POST /tickets/save`

- Nécessite la permission `save_ticket`
- Reçoit (JSON) : résultat d'analyse + commentaire + tags
- **Déduplication** : impossible de sauvegarder deux fois le même hash par utilisateur
- Retourne l'ID du ticket + URL de redirection

### Liste des Tickets — `GET /tickets/`

- **Admin** : voit tous les tickets de tous les utilisateurs
- **Analyst** : voit uniquement ses propres tickets
- Triés par date de création décroissante

### Détail d'un Ticket — `GET /tickets/<id>`

Contient :
- Toutes les données d'analyse complètes
- Section **notes collaboratives**
- Gestion des **tags**
- Bouton **renommer** le fichier
- Bouton **supprimer** le ticket
- Lien direct **VirusTotal**
- Bouton **télécharger le PDF**

### Notes — `POST /tickets/<id>/notes`

- Max **2 000 caractères** par note
- Horodatées avec l'auteur affiché
- Affichées en ordre chronologique

### Tags — `POST /tickets/<id>/tags`

- Max **10 tags** par ticket, **30 caractères** max par tag
- Normalisés : lowercase, déduplication automatique
- Suggestions prédéfinies :

```
ransomware · apt · trojan · spyware · keylogger · c2 · dropper
confirmed-clean · false-positive · phishing · backdoor · worm
```

### Actions sur un Ticket

| Action | Route | Méthode |
|--------|-------|---------|
| Voir la liste | `/tickets/` | GET |
| Créer | `/tickets/save` | POST |
| Voir le détail | `/tickets/<id>` | GET |
| Ajouter une note | `/tickets/<id>/notes` | POST |
| Modifier les tags | `/tickets/<id>/tags` | POST |
| Renommer | `/tickets/<id>/rename` | POST |
| Supprimer | `/tickets/<id>/delete` | POST |

---

## 7. Génération PDF

### Route — `POST /pdf/generate/<ticket_id>`

**Prérequis :** permission `generate_pdf`

**Processus :**
1. Vérification de la permission
2. Réception des options (optionnelles) :
   - Nom du client
   - Logo client (image uploadée → encodée en **data URI base64**)
3. Rendu du template `pdf/report_pdf.html` avec :
   - Données complètes du ticket
   - Données d'analyse (`result_json`)
   - Nom du client + logo
   - Horodatage de génération
4. **WeasyPrint** convertit le HTML → PDF binaire en mémoire
5. Téléchargement avec nom de fichier :
   ```
   DATAPROTECT-{CLIENT}-{TICKET_ID}.pdf
   ```

---

## 8. Interface Admin

### Dashboard — `/admin/dashboard`

| Section | Contenu |
|---------|---------|
| KPIs | Total utilisateurs, analystes, tickets, tickets (30 derniers jours) |
| Distribution menaces | Répartition CRITICAL / HIGH / MEDIUM / LOW |
| Alertes critiques | Top 10 tickets avec score ≥ 75 |
| Activité récente | 15 dernières analyses toutes personnes confondues |
| Top YARA | 8 règles YARA les plus déclenchées |
| Activité par analyste | Nombre de tickets + date de dernière analyse |

### Gestion Utilisateurs — `/admin/users`

| Action | Description |
|--------|-------------|
| Créer un utilisateur | Username, email, mot de passe, rôle |
| Activer / désactiver | Toggle `is_active` (AJAX) |
| Modifier permissions | `save_ticket` + `generate_pdf` (AJAX) |
| Réinitialiser MDP | Admin impose un nouveau mot de passe |
| Supprimer | Suppression définitive avec confirmation |

### Alertes — `/admin/alerts`

Vue dédiée de **tous les tickets critiques** (score ≥ 75) pour un suivi rapide sans naviguer dans le dashboard.

> Toutes les routes admin sont protégées par le décorateur `@admin_required`.

---

## 9. Sécurité Globale

### Protection des Requêtes

| Mécanisme | Détails |
|-----------|---------|
| **CSRF** | Flask-WTF sur tous les POST / PUT / PATCH / DELETE |
| **Rate Limiting** | Login : 10/min · Analyse : 20/h (par IP) |
| **Headers HTTP** | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin` |
| **CSP** | `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com` |

### Gestion des Fichiers

- Fichiers **jamais stockés définitivement** — supprimés dans le bloc `finally`
- Nommage aléatoire via UUID (pas de collision possible)
- `secure_filename()` empêche les traversées de répertoires (path traversal)
- Validation de l'extension + magic bytes

### Logs

- **Rotating file handlers** : 5 MB par fichier, 5 fichiers de rotation
- Fichiers de logs : `analyzer.log`, `access.log`, `error.log`
- Événements loggés : tentatives de login échouées, actions admin, uploads, erreurs

---

## 10. Configuration & Déploiement

### Variables d'Environnement (`.env`)

```env
SECRET_KEY=<clé hex 32 octets>
VT_API_KEY=<clé API VirusTotal>
ADMIN_DEFAULT_PASSWORD=<mot de passe admin initial>
FLASK_ENV=development|production
HTTPS=true|false
LOG_LEVEL=DEBUG|INFO|WARNING|ERROR|CRITICAL
```

### Configurations

| Config | DEBUG | SESSION_COOKIE_SECURE |
|--------|-------|-----------------------|
| Development | True | False (HTTP autorisé) |
| Production | False | True (HTTPS obligatoire) |

### Installation (Ubuntu/Debian)

```bash
# Dépendances système
sudo apt install python3-pip python3-venv \
  libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
  libgdk-pixbuf2.0-0 libffi-dev libxml2-dev libxslt1-dev \
  file libmagic1 libgirepository1.0-dev gir1.2-pango-1.0

# Installation Python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Création des répertoires
mkdir -p database logs uploads app/static/uploads/logos
```

### Génération de la SECRET_KEY

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Premier Démarrage

```bash
# Développement
python run.py

# Production (Gunicorn)
gunicorn --bind 0.0.0.0:80 --workers 4 --timeout 120 run:app
```

1. Accéder à `http://<IP>:5000`
2. Login avec `admin` / `ADMIN_DEFAULT_PASSWORD`
3. **Changer immédiatement le mot de passe admin** via `/admin/users`
4. Créer les comptes analystes
5. Assigner les permissions par utilisateur

### Déploiement Systemd (Production)

```bash
sudo cp static-analyzer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable static-analyzer
sudo systemctl start static-analyzer
sudo systemctl status static-analyzer
```

---

## 11. Dépendances

| Package | Version | Rôle |
|---------|---------|------|
| Flask | 3.0.3 | Framework web |
| Flask-SQLAlchemy | 3.1.1 | ORM |
| Flask-Login | 0.6.3 | Gestion sessions |
| Flask-WTF | 1.2.1 | Formulaires + CSRF |
| Flask-Limiter | 3.8.0 | Rate limiting |
| Werkzeug | 3.0.3 | Utilitaires WSGI |
| WTForms | 3.1.2 | Validation formulaires |
| SQLAlchemy | 2.0.31 | ORM core |
| pefile | 2023.2.7 | Parsing binaires PE |
| yara-python | 4.5.1 | Moteur YARA |
| python-magic | 0.4.27 | Détection type fichier |
| pypdf | 4.3.1 | Lecture PDF |
| Pillow | 10.4.0 | Traitement images |
| python-docx | 1.1.2 | Lecture DOCX |
| WeasyPrint | 62.3 | Génération PDF |
| requests | 2.32.3 | Client HTTP (VirusTotal) |
| gunicorn | 22.0.0 | Serveur WSGI production |
| python-dotenv | 1.0.1+ | Chargement `.env` |

---

## 12. Routes & Endpoints

### Authentification (`/auth`)

| Méthode | Route | Auth requise | Description |
|---------|-------|-------------|-------------|
| GET / POST | `/auth/login` | Non | Formulaire de connexion |
| GET | `/auth/logout` | Oui | Déconnexion |

### Analyse (`/`)

| Méthode | Route | Auth | Rate Limit | Description |
|---------|-------|------|-----------|-------------|
| GET | `/` | Oui | — | Page d'upload |
| POST | `/analyze` | Oui | 20/h | Analyse un fichier |
| GET | `/vt-check/<sha256>` | Oui | — | AJAX : lookup VirusTotal |

### Tickets (`/tickets`)

| Méthode | Route | Permission | Description |
|---------|-------|-----------|-------------|
| GET | `/tickets/` | Login | Liste des tickets |
| POST | `/tickets/save` | `save_ticket` | Créer un ticket |
| GET | `/tickets/<id>` | Login | Détail d'un ticket |
| POST | `/tickets/<id>/notes` | Login | Ajouter une note |
| POST | `/tickets/<id>/tags` | Login | Modifier les tags |
| POST | `/tickets/<id>/rename` | Login | Renommer le fichier |
| POST | `/tickets/<id>/delete` | Login | Supprimer le ticket |

### PDF (`/pdf`)

| Méthode | Route | Permission | Description |
|---------|-------|-----------|-------------|
| GET / POST | `/pdf/generate/<ticket_id>` | `generate_pdf` | Générer + télécharger PDF |

### Admin (`/admin`)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/admin/dashboard` | Dashboard général |
| GET | `/admin/users` | Liste des utilisateurs |
| POST | `/admin/users/create` | Créer un utilisateur |
| POST | `/admin/users/<id>/toggle-active` | Activer/désactiver |
| POST | `/admin/users/<id>/permissions` | Modifier permissions (JSON) |
| POST | `/admin/users/<id>/reset-password` | Réinitialiser MDP |
| POST | `/admin/users/<id>/delete` | Supprimer utilisateur |
| GET | `/admin/alerts` | Alertes critiques |

---

## 13. Modèles de Données

### Modèle `User`

| Champ | Type | Description |
|-------|------|-------------|
| `id` | PK Integer | Identifiant unique |
| `username` | String (unique) | Nom d'utilisateur |
| `email` | String (unique) | Adresse email |
| `password_hash` | String | Hash PBKDF2:SHA256 |
| `role` | Enum | `ADMIN` ou `ANALYST` |
| `is_active` | Boolean | Compte actif ou non |
| `permissions` | JSON | `{"save_ticket": bool, "generate_pdf": bool}` |
| `created_at` | DateTime | Date de création |
| `last_login` | DateTime | Dernière connexion |

### Modèle `Ticket`

| Champ | Type | Description |
|-------|------|-------------|
| `id` | PK Integer | Identifiant unique |
| `user_id` | FK → User | Propriétaire |
| `filename` | String | Nom du fichier analysé |
| `sha256` / `md5` / `sha1` | String | Hashes d'identification |
| `file_type` | String | PE, PDF, ELF, DOCX, etc. |
| `threat_score` | Integer (0–100) | Score de menace |
| `threat_level` | Enum | LOW / MEDIUM / HIGH / CRITICAL |
| `result_json` | Text | Résultat complet (JSON sérialisé) |
| `comment` | String (1000) | Commentaire initial |
| `tags` | JSON | Liste de tags normalisés |
| `created_at` / `updated_at` | DateTime | Horodatages |
| `notes` | Relation | → TicketNote (cascade delete) |

### Modèle `TicketNote`

| Champ | Type | Description |
|-------|------|-------------|
| `id` | PK Integer | Identifiant unique |
| `ticket_id` | FK → Ticket | Ticket associé |
| `user_id` | FK → User | Auteur (nullable) |
| `content` | Text (2000) | Contenu de la note |
| `created_at` | DateTime | Horodatage |

---

## 14. Points à Améliorer

| Problème | Impact | Priorité |
|----------|--------|----------|
| Pas de migrations DB (Alembic) | Changements de schéma manuels | Moyenne |
| Rate limiting en mémoire | Compteurs perdus au redémarrage | Faible (Redis en prod) |
| Pas d'analyse en masse | Un seul fichier à la fois | Faible |
| Pas de 2FA pour l'admin | Sécurité renforcée souhaitée | Haute |
| Pas d'audit log détaillé | Traçabilité limitée des actions | Moyenne |
| Export JSON/CSV tickets | Interopérabilité externe limitée | Faible |
| Règles YARA non-updatables | Admin ne peut pas ajouter de règles | Moyenne |
| Pas de notifications | Aucune alerte email/webhook | Faible |
| Pas d'analyse planifiée | Re-analyse manuelle uniquement | Faible |
| Pas de comparaison de rapports | Analyse comparative impossible | Faible |

---
