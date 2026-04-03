"""
app/analysis/engine.py — Orchestrateur principal d'analyse.
Appelle tous les modules spécialisés et assemble le rapport final.
"""

import os
import math
import string
import hashlib
import logging
from datetime import datetime, timezone

from flask import current_app

logger = logging.getLogger(__name__)


# ── Hashes ────────────────────────────────────────────────────────────────────

def calculate_hashes(file_path: str) -> dict:
    hashes = {}
    with open(file_path, "rb") as f:
        data = f.read()
    hashes["md5"]    = hashlib.md5(data).hexdigest()
    hashes["sha1"]   = hashlib.sha1(data).hexdigest()
    hashes["sha256"] = hashlib.sha256(data).hexdigest()
    return hashes


# ── Entropy ───────────────────────────────────────────────────────────────────

def calculate_entropy(file_path: str) -> float:
    with open(file_path, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 6)


# ── Strings extraction ────────────────────────────────────────────────────────

def extract_strings(file_path: str, min_length: int = 4) -> list:
    strings_list = []
    with open(file_path, "rb") as f:
        raw = f.read()
    result = ""
    for b in raw:
        c = chr(b)
        if c in string.printable and c not in ("\n", "\r", "\t"):
            result += c
        else:
            if len(result) >= min_length:
                strings_list.append(result)
            result = ""
    if len(result) >= min_length:
        strings_list.append(result)
    return strings_list


# ── File type detection ───────────────────────────────────────────────────────

def detect_file_type(file_path: str, filename: str) -> str:
    """Détecte le type de fichier via magic bytes et extension."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)

        magic_map = {
            b"MZ":           "PE",
            b"\x7fELF":      "ELF",
            b"%PDF":         "PDF",
            b"PK\x03\x04":   "ZIP_BASED",   # ZIP, DOCX, XLSX, JAR...
            b"\xff\xd8\xff":  "JPEG",
            b"\x89PNG":       "PNG",
            b"GIF8":          "GIF",
            b"BM":            "BMP",
            b"Rar!":          "RAR",
            b"7z\xbc\xaf":    "7ZIP",
        }

        for magic, ftype in magic_map.items():
            if header.startswith(magic):
                # Affine ZIP_BASED par extension
                if ftype == "ZIP_BASED":
                    ext = os.path.splitext(filename)[1].lower()
                    return {"docx": "DOCX", "xlsx": "XLSX",
                            "jar": "JAR", "zip": "ZIP"}.get(ext.lstrip("."), "ZIP_BASED")
                return ftype
    except Exception:
        pass

    # Fallback sur l'extension
    ext = os.path.splitext(filename)[1].lower().lstrip(".")
    return ext.upper() if ext else "UNKNOWN"


# ── PE analysis ───────────────────────────────────────────────────────────────

def analyze_pe(file_path: str) -> dict:
    """Analyse un fichier PE (exe, dll, sys)."""
    result = {"imports": [], "compile_time": "Unknown", "sections": []}
    try:
        import pefile
        pe = pefile.PE(file_path)

        # Compile time
        from datetime import datetime
        ts = pe.FILE_HEADER.TimeDateStamp
        result["compile_time"] = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="replace")
                for imp in entry.imports:
                    if imp.name:
                        result["imports"].append(f"{dll}:{imp.name.decode(errors='replace')}")
        result["imports"] = result["imports"][:50]

        # Sections
        for section in pe.sections:
            name = section.Name.decode(errors="replace").strip("\x00")
            result["sections"].append({
                "name":     name,
                "size":     section.SizeOfRawData,
                "virtual":  section.VirtualAddress,
                "entropy":  round(section.get_entropy(), 4),
            })
    except Exception as e:
        result["error"] = str(e)
    return result


# ── PDF analysis ──────────────────────────────────────────────────────────────

def analyze_pdf(file_path: str) -> dict:
    """Analyse un fichier PDF : JS embarqué, URLs, métadonnées."""
    result = {"javascript": [], "urls": [], "metadata": {}, "suspicious": []}
    try:
        import pypdf
        reader = pypdf.PdfReader(file_path)

        # Métadonnées
        meta = reader.metadata
        if meta:
            result["metadata"] = {
                "author":   str(meta.get("/Author", "")),
                "creator":  str(meta.get("/Creator", "")),
                "producer": str(meta.get("/Producer", "")),
                "created":  str(meta.get("/CreationDate", "")),
            }

        # Lecture du texte pour trouver URLs
        import re
        url_pattern = re.compile(r"https?://[^\s<>\"]+")
        for page in reader.pages:
            try:
                text = page.extract_text() or ""
                result["urls"].extend(url_pattern.findall(text))
            except Exception:
                pass

        # Détection JS (via lecture brute)
        with open(file_path, "rb") as f:
            raw = f.read().decode(errors="replace")
        if "/JavaScript" in raw or "/JS" in raw:
            result["javascript"].append("JavaScript detected in PDF structure")
            result["suspicious"].append("Embedded JavaScript — potential exploit")
        if "/Launch" in raw:
            result["suspicious"].append("/Launch action detected — can execute commands")
        if "/EmbeddedFile" in raw:
            result["suspicious"].append("Embedded file detected")
        if "/OpenAction" in raw:
            result["suspicious"].append("/OpenAction detected — auto-executes on open")

        result["urls"] = list(set(result["urls"]))[:20]

    except ImportError:
        result["error"] = "pypdf not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Image analysis ────────────────────────────────────────────────────────────

def analyze_image(file_path: str) -> dict:
    """Analyse une image : EXIF, stéganographie basique, anomalies."""
    result = {"exif": {}, "suspicious": [], "file_type_match": True}
    try:
        from PIL import Image
        import PIL.ExifTags

        img = Image.open(file_path)
        result["format"]  = img.format
        result["mode"]    = img.mode
        result["size"]    = img.size

        # EXIF data
        exif_data = img._getexif() if hasattr(img, "_getexif") else None
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = PIL.ExifTags.TAGS.get(tag_id, tag_id)
                result["exif"][str(tag)] = str(value)[:100]

        # Détection stéganographie basique : entropie élevée dans une image
        # Une image normale a une entropie < 7.5
        img_entropy = calculate_entropy(file_path)
        if img_entropy > 7.5:
            result["suspicious"].append(
                f"Entropy élevée ({img_entropy:.2f}) — possible stéganographie ou compression"
            )

        # Détection de texte caché basique : chercher strings dans l'image
        strings = extract_strings(file_path, min_length=8)
        suspicious_strs = [s for s in strings if any(
            kw in s.lower() for kw in ["http", "exec", "shell", "eval", "base64"]
        )]
        if suspicious_strs:
            result["suspicious"].extend([
                f"String suspecte dans l'image: {s[:80]}" for s in suspicious_strs[:5]
            ])

    except ImportError:
        result["error"] = "Pillow not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Office analysis ───────────────────────────────────────────────────────────

def analyze_office(file_path: str, file_type: str) -> dict:
    """Analyse les fichiers Office : macros VBA, OLE objects."""
    result = {"macros": [], "ole_objects": [], "suspicious": []}
    try:
        import zipfile
        import re

        # Les .docx/.xlsx sont des ZIPs
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path) as z:
                names = z.namelist()
                # Chercher les macros
                macro_files = [n for n in names if "vba" in n.lower() or "macro" in n.lower()]
                if macro_files:
                    result["macros"].extend(macro_files)
                    result["suspicious"].append("Macros VBA détectées dans le document")

                # Chercher les relations suspectes (external links)
                for name in names:
                    if "rels" in name:
                        try:
                            content = z.read(name).decode(errors="replace")
                            urls = re.findall(r'Target="(https?://[^"]+)"', content)
                            if urls:
                                result["suspicious"].extend([
                                    f"External URL dans les relations: {u}" for u in urls[:5]
                                ])
                        except Exception:
                            pass
    except Exception as e:
        result["error"] = str(e)
    return result


# ── YARA ─────────────────────────────────────────────────────────────────────

def run_yara_scan(file_path: str) -> list:
    from app.analysis.yara_engine import YARA_RULES_SOURCE
    matches = []
    try:
        import yara
        rules = yara.compile(source=YARA_RULES_SOURCE)
        raw   = rules.match(file_path)
        for m in raw:
            meta = m.meta if m.meta else {}
            matches.append({
                "rule":        m.rule,
                "description": meta.get("description", ""),
                "severity":    meta.get("severity", "unknown"),
                "mitre":       meta.get("mitre", ""),
            })
    except Exception as e:
        matches.append({"rule": "YARA_ERROR", "description": str(e),
                        "severity": "unknown", "mitre": ""})
    return matches


# ── VirusTotal ────────────────────────────────────────────────────────────────

def check_virustotal(sha256: str) -> dict | str:
    import requests
    api_key = current_app.config.get("VT_API_KEY", "")
    if not api_key or api_key == "REMPLACER_PAR_CLE_REELLE":
        return "VT_API_KEY non configurée"

    url     = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data["data"]["attributes"]["last_analysis_stats"]
        if resp.status_code == 404:
            return "Fichier non trouvé dans VirusTotal"
        return f"Erreur VirusTotal: HTTP {resp.status_code}"
    except Exception as e:
        return f"VirusTotal check failed: {e}"


# ── Threat Score ──────────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 10, "low": 5}


def calculate_threat_score(entropy, yara_matches, suspicious_data, virustotal) -> dict:
    score = 0

    if entropy > 7.5:   score += 30
    elif entropy > 7.0: score += 20
    elif entropy > 6.0: score += 10

    for m in yara_matches:
        score += SEVERITY_WEIGHTS.get(m.get("severity", "low"), 5)

    # Suspicious strings score
    if isinstance(suspicious_data, dict):
        by_cat = suspicious_data.get("by_category", {})
        for cat, items in by_cat.items():
            for item in items:
                score += SEVERITY_WEIGHTS.get(item.get("severity", "low"), 5) // 3
        score += min(len(suspicious_data.get("urls", [])) * 5, 15)
        score += min(len(suspicious_data.get("commands", [])) * 5, 15)
    else:
        # Compat ancien format
        score += min(len(suspicious_data.get("urls", [])) * 5, 15)
        score += min(len(suspicious_data.get("commands", [])) * 5, 15)

    if isinstance(virustotal, dict):
        malicious  = virustotal.get("malicious", 0)
        suspicious = virustotal.get("suspicious", 0)
        if malicious > 20:   score += 40
        elif malicious > 10: score += 30
        elif malicious > 5:  score += 20
        elif malicious > 0:  score += 10
        score += min(suspicious * 2, 10)

    score = min(score, 100)

    if score >= 75:   level, color = "CRITICAL", "#ef4444"
    elif score >= 50: level, color = "HIGH",     "#f97316"
    elif score >= 25: level, color = "MEDIUM",   "#eab308"
    else:             level, color = "LOW",       "#22c55e"

    return {"score": score, "level": level, "color": color}


# ═════════════════════════════════════════════════════════════════════════════
#  ORCHESTRATEUR PRINCIPAL
# ═════════════════════════════════════════════════════════════════════════════

def run_full_analysis(file_path: str, filename: str) -> dict:
    """
    Lance l'analyse complète sur un fichier.
    Retourne le dictionnaire complet du rapport.
    """
    from app.analysis.suspicious_strings import analyze_strings
    from app.analysis.mitre import enrich_mitre

    logger.info("Début analyse: %s", filename)

    # Hashes
    hashes    = calculate_hashes(file_path)
    entropy   = calculate_entropy(file_path)
    file_type = detect_file_type(file_path, filename)
    strings   = extract_strings(file_path)

    # Suspicious strings (nouveau moteur)
    susp_result = analyze_strings(strings)

    # Analyse spécialisée selon le type
    type_specific = {}
    if file_type == "PE":
        pe_data = analyze_pe(file_path)
        type_specific = {
            "imports":      pe_data.get("imports", []),
            "compile_time": pe_data.get("compile_time", "Unknown"),
            "sections":     pe_data.get("sections", []),
        }
    elif file_type == "PDF":
        type_specific = {"pdf_analysis": analyze_pdf(file_path)}
    elif file_type in ("JPEG", "PNG", "GIF", "BMP"):
        type_specific = {"image_analysis": analyze_image(file_path)}
    elif file_type in ("DOCX", "XLSX", "ZIP_BASED"):
        type_specific = {"office_analysis": analyze_office(file_path, file_type)}

    # YARA + MITRE
    yara_hits  = run_yara_scan(file_path)
    mitre_hits = enrich_mitre(yara_hits)

    # VirusTotal
    vt = check_virustotal(hashes["sha256"])

    # Score
    threat = calculate_threat_score(entropy, yara_hits, susp_result, vt)

    result = {
        "filename":          filename,
        "file_type":         file_type,
        "analysis_time":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "hashes":            hashes,
        "entropy":           entropy,
        "compile_time":      type_specific.get("compile_time", "N/A"),
        "imports":           type_specific.get("imports", []),
        "sections":          type_specific.get("sections", []),
        "suspicious_strings": susp_result,
        "virustotal":        vt,
        "vt_url":            f"https://www.virustotal.com/gui/file/{hashes['sha256']}",
        "yara_matches":      yara_hits,
        "mitre_techniques":  mitre_hits,
        "threat_score":      threat,
        **{k: v for k, v in type_specific.items()
           if k not in ("imports", "compile_time", "sections")},
    }

    logger.info("Analyse terminée: %s — score=%d", filename, threat["score"])
    return result