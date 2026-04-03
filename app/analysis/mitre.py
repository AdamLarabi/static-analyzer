"""
app/analysis/mitre.py — Mapping MITRE ATT&CK complet.
"""

MITRE_MAPPING = {
    "T1486": {"tactic": "Impact", "name": "Data Encrypted for Impact",
              "url": "https://attack.mitre.org/techniques/T1486",
              "description": "Adversaire chiffre les fichiers pour rançonner la victime."},
    "T1055": {"tactic": "Defense Evasion / Privilege Escalation", "name": "Process Injection",
              "url": "https://attack.mitre.org/techniques/T1055",
              "description": "Code injecté dans l'espace d'adresse d'un autre processus."},
    "T1041": {"tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel",
              "url": "https://attack.mitre.org/techniques/T1041",
              "description": "Données exfiltrées via un canal C2 établi."},
    "T1547": {"tactic": "Persistence", "name": "Boot or Logon Autostart Execution",
              "url": "https://attack.mitre.org/techniques/T1547",
              "description": "Persistance via modification des emplacements d'autostart."},
    "T1548": {"tactic": "Privilege Escalation", "name": "Abuse Elevation Control Mechanism",
              "url": "https://attack.mitre.org/techniques/T1548",
              "description": "Contourne l'UAC ou manipule les tokens d'accès."},
    "T1027": {"tactic": "Defense Evasion", "name": "Obfuscated Files or Information",
              "url": "https://attack.mitre.org/techniques/T1027",
              "description": "Binaire packé ou obfusqué pour compliquer l'analyse."},
    "T1056": {"tactic": "Collection / Credential Access", "name": "Input Capture",
              "url": "https://attack.mitre.org/techniques/T1056",
              "description": "Capture des frappes clavier ou du presse-papiers."},
    "T1622": {"tactic": "Defense Evasion", "name": "Debugger Evasion",
              "url": "https://attack.mitre.org/techniques/T1622",
              "description": "Détecte les environnements de débogage."},
    "T1059": {"tactic": "Execution", "name": "Command and Scripting Interpreter",
              "url": "https://attack.mitre.org/techniques/T1059",
              "description": "Utilise des interpréteurs de commandes/scripts."},
    "T1105": {"tactic": "Command and Control", "name": "Ingress Tool Transfer",
              "url": "https://attack.mitre.org/techniques/T1105",
              "description": "Téléchargement d'outils depuis une source externe."},
    "T1003": {"tactic": "Credential Access", "name": "OS Credential Dumping",
              "url": "https://attack.mitre.org/techniques/T1003",
              "description": "Extraction des credentials depuis la mémoire OS."},
    "T1021": {"tactic": "Lateral Movement", "name": "Remote Services",
              "url": "https://attack.mitre.org/techniques/T1021",
              "description": "Utilise des services distants pour se déplacer."},
    "T1562": {"tactic": "Defense Evasion", "name": "Impair Defenses",
              "url": "https://attack.mitre.org/techniques/T1562",
              "description": "Désactive ou contourne les mécanismes de défense."},
    "T1490": {"tactic": "Impact", "name": "Inhibit System Recovery",
              "url": "https://attack.mitre.org/techniques/T1490",
              "description": "Supprime les sauvegardes et points de restauration."},
    "T1070": {"tactic": "Defense Evasion", "name": "Indicator Removal",
              "url": "https://attack.mitre.org/techniques/T1070",
              "description": "Efface les traces d'activité (logs, fichiers temp)."},
    "T1134": {"tactic": "Privilege Escalation", "name": "Access Token Manipulation",
              "url": "https://attack.mitre.org/techniques/T1134",
              "description": "Manipule les tokens Windows pour obtenir des privilèges."},
    "T1071": {"tactic": "Command and Control", "name": "Application Layer Protocol",
              "url": "https://attack.mitre.org/techniques/T1071",
              "description": "C2 via protocoles applicatifs (HTTP, DNS, IRC)."},
    "T1137": {"tactic": "Persistence", "name": "Office Application Startup",
              "url": "https://attack.mitre.org/techniques/T1137",
              "description": "Persistance via macros Office ou add-ins."},
    "T1204": {"tactic": "Execution", "name": "User Execution",
              "url": "https://attack.mitre.org/techniques/T1204",
              "description": "L'utilisateur exécute lui-même le payload malveillant."},
    "T1140": {"tactic": "Defense Evasion", "name": "Deobfuscate/Decode Files or Information",
              "url": "https://attack.mitre.org/techniques/T1140",
              "description": "Décode du contenu obfusqué (base64, XOR, etc.)."},
    "T1113": {"tactic": "Collection", "name": "Screen Capture",
              "url": "https://attack.mitre.org/techniques/T1113",
              "description": "Capture des captures d'écran de la victime."},
    "T1115": {"tactic": "Collection", "name": "Clipboard Data",
              "url": "https://attack.mitre.org/techniques/T1115",
              "description": "Collecte les données du presse-papiers."},
}


def enrich_mitre(yara_matches: list) -> list:
    """Enrichit les matches YARA avec les données MITRE ATT&CK."""
    seen    = set()
    results = []
    for m in yara_matches:
        tid = m.get("mitre", "")
        # Gère les TIDs avec sous-technique (T1059.001 → T1059)
        base_tid = tid.split(".")[0] if "." in tid else tid
        for lookup in [tid, base_tid]:
            if lookup and lookup in MITRE_MAPPING and lookup not in seen:
                seen.add(lookup)
                results.append({**MITRE_MAPPING[lookup], "technique_id": lookup})
                break
    return results