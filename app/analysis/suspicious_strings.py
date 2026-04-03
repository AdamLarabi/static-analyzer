"""
app/analysis/suspicious_strings.py
Détection des strings suspectes dans un binaire.

Approche combinée :
  1. Liste large catégorisée (~200 entrées) — correspondance exacte/partielle
  2. Regex dynamiques — couvrent les patterns que la liste statique ne peut pas capturer
     (encodage base64, obfuscation, chemins dynamiques, etc.)

Chaque correspondance retourne : { string, category, description, severity, mitre }
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class SuspiciousMatch:
    string:      str
    category:    str
    description: str
    severity:    str          # critical | high | medium | low
    mitre:       str = ""
    match_type:  str = "keyword"  # keyword | regex


# ═════════════════════════════════════════════════════════════════════════════
#  1. LISTE LARGE CATÉGORISÉE
# ═════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_KEYWORDS: List[Dict] = [

    # ── Shells & Execution ────────────────────────────────────────────────────
    {"s": "cmd.exe",              "cat": "execution",       "sev": "high",   "mitre": "T1059.003", "desc": "Windows Command Shell"},
    {"s": "powershell",           "cat": "execution",       "sev": "high",   "mitre": "T1059.001", "desc": "PowerShell execution"},
    {"s": "powershell.exe",       "cat": "execution",       "sev": "high",   "mitre": "T1059.001", "desc": "PowerShell binary"},
    {"s": "pwsh",                 "cat": "execution",       "sev": "high",   "mitre": "T1059.001", "desc": "PowerShell Core"},
    {"s": "wscript",              "cat": "execution",       "sev": "high",   "mitre": "T1059.005", "desc": "Windows Script Host"},
    {"s": "cscript",              "cat": "execution",       "sev": "high",   "mitre": "T1059.005", "desc": "Windows Script Host (console)"},
    {"s": "mshta.exe",            "cat": "execution",       "sev": "critical","mitre": "T1218.005","desc": "MSHTA LOLBin execution"},
    {"s": "mshta",                "cat": "execution",       "sev": "critical","mitre": "T1218.005","desc": "MSHTA execution"},
    {"s": "wmic",                 "cat": "execution",       "sev": "high",   "mitre": "T1047",     "desc": "WMI command execution"},
    {"s": "wmic.exe",             "cat": "execution",       "sev": "high",   "mitre": "T1047",     "desc": "WMI binary"},
    {"s": "rundll32",             "cat": "execution",       "sev": "high",   "mitre": "T1218.011", "desc": "RunDLL32 LOLBin"},
    {"s": "regsvr32",             "cat": "execution",       "sev": "high",   "mitre": "T1218.010", "desc": "Regsvr32 LOLBin"},
    {"s": "regsvcs",              "cat": "execution",       "sev": "high",   "mitre": "T1218.009", "desc": "Regsvcs LOLBin"},
    {"s": "regasm",               "cat": "execution",       "sev": "high",   "mitre": "T1218.009", "desc": "Regasm LOLBin"},
    {"s": "installutil",          "cat": "execution",       "sev": "high",   "mitre": "T1218.004", "desc": "InstallUtil LOLBin"},
    {"s": "msiexec",              "cat": "execution",       "sev": "medium", "mitre": "T1218.007", "desc": "MSI execution"},
    {"s": "certutil",             "cat": "execution",       "sev": "critical","mitre": "T1140",    "desc": "CertUtil for decode/download"},
    {"s": "certutil.exe",         "cat": "execution",       "sev": "critical","mitre": "T1140",    "desc": "CertUtil binary"},
    {"s": "bitsadmin",            "cat": "download",        "sev": "high",   "mitre": "T1197",     "desc": "BITSAdmin file transfer"},
    {"s": "expand.exe",           "cat": "execution",       "sev": "medium", "mitre": "T1218",     "desc": "Expand LOLBin"},
    {"s": "forfiles",             "cat": "execution",       "sev": "medium", "mitre": "T1059.003", "desc": "Forfiles execution"},
    {"s": "pcalua",               "cat": "execution",       "sev": "medium", "mitre": "T1218",     "desc": "PCAlua LOLBin"},
    {"s": "bash.exe",             "cat": "execution",       "sev": "medium", "mitre": "T1059.004", "desc": "Bash (WSL)"},
    {"s": "/bin/sh",              "cat": "execution",       "sev": "medium", "mitre": "T1059.004", "desc": "Unix shell"},
    {"s": "/bin/bash",            "cat": "execution",       "sev": "medium", "mitre": "T1059.004", "desc": "Bash shell"},
    {"s": "python.exe",           "cat": "execution",       "sev": "medium", "mitre": "T1059.006", "desc": "Python execution"},
    {"s": "python3",              "cat": "execution",       "sev": "medium", "mitre": "T1059.006", "desc": "Python3 execution"},
    {"s": "perl",                 "cat": "execution",       "sev": "medium", "mitre": "T1059",     "desc": "Perl script execution"},
    {"s": "ruby",                 "cat": "execution",       "sev": "medium", "mitre": "T1059",     "desc": "Ruby execution"},
    {"s": "node.exe",             "cat": "execution",       "sev": "medium", "mitre": "T1059",     "desc": "Node.js execution"},

    # ── Download / Stager ─────────────────────────────────────────────────────
    {"s": "wget",                 "cat": "download",        "sev": "high",   "mitre": "T1105",     "desc": "File download tool"},
    {"s": "curl",                 "cat": "download",        "sev": "high",   "mitre": "T1105",     "desc": "File transfer tool"},
    {"s": "Invoke-WebRequest",    "cat": "download",        "sev": "critical","mitre": "T1105",    "desc": "PowerShell download"},
    {"s": "IWR",                  "cat": "download",        "sev": "high",   "mitre": "T1105",     "desc": "Invoke-WebRequest alias"},
    {"s": "Invoke-Expression",    "cat": "execution",       "sev": "critical","mitre": "T1059.001","desc": "PowerShell IEX execution"},
    {"s": "IEX",                  "cat": "execution",       "sev": "critical","mitre": "T1059.001","desc": "IEX alias"},
    {"s": "DownloadFile",         "cat": "download",        "sev": "high",   "mitre": "T1105",     "desc": ".NET WebClient download"},
    {"s": "DownloadString",       "cat": "download",        "sev": "critical","mitre": "T1105",    "desc": ".NET download & exec"},
    {"s": "Net.WebClient",        "cat": "download",        "sev": "high",   "mitre": "T1105",     "desc": ".NET WebClient"},
    {"s": "WebRequest",           "cat": "download",        "sev": "medium", "mitre": "T1105",     "desc": "Web request"},
    {"s": "HttpWebRequest",       "cat": "download",        "sev": "medium", "mitre": "T1071",     "desc": ".NET HTTP request"},
    {"s": "URLDownloadToFile",    "cat": "download",        "sev": "high",   "mitre": "T1105",     "desc": "WinAPI file download"},
    {"s": "tftp",                 "cat": "download",        "sev": "high",   "mitre": "T1105",     "desc": "TFTP file transfer"},
    {"s": "ftp",                  "cat": "download",        "sev": "medium", "mitre": "T1105",     "desc": "FTP transfer"},

    # ── Credential Access ─────────────────────────────────────────────────────
    {"s": "mimikatz",             "cat": "credential_access","sev": "critical","mitre": "T1003",   "desc": "Mimikatz credential dumper"},
    {"s": "sekurlsa",             "cat": "credential_access","sev": "critical","mitre": "T1003.001","desc": "Mimikatz sekurlsa module"},
    {"s": "lsadump",              "cat": "credential_access","sev": "critical","mitre": "T1003.002","desc": "LSA secrets dump"},
    {"s": "wdigest",              "cat": "credential_access","sev": "critical","mitre": "T1003",   "desc": "WDigest credential extraction"},
    {"s": "SAMRQueryUserInfo",    "cat": "credential_access","sev": "high",   "mitre": "T1003.002","desc": "SAM database query"},
    {"s": "NtlmHash",             "cat": "credential_access","sev": "high",   "mitre": "T1003",   "desc": "NTLM hash reference"},
    {"s": "pass-the-hash",        "cat": "credential_access","sev": "critical","mitre": "T1550.002","desc": "Pass-the-hash technique"},
    {"s": "kerberoast",           "cat": "credential_access","sev": "critical","mitre": "T1558.003","desc": "Kerberoasting attack"},
    {"s": "procdump",             "cat": "credential_access","sev": "high",   "mitre": "T1003.001","desc": "Process memory dump"},
    {"s": "comsvcs.dll",          "cat": "credential_access","sev": "high",   "mitre": "T1003.001","desc": "LSASS dump via comsvcs"},
    {"s": "MiniDump",             "cat": "credential_access","sev": "high",   "mitre": "T1003.001","desc": "Memory miniDump"},
    {"s": "password",             "cat": "credential_access","sev": "medium", "mitre": "T1555",   "desc": "Password string reference"},
    {"s": "passwd",               "cat": "credential_access","sev": "medium", "mitre": "T1555",   "desc": "Password string reference"},
    {"s": "credentials",          "cat": "credential_access","sev": "medium", "mitre": "T1555",   "desc": "Credentials reference"},
    {"s": "GetPassword",          "cat": "credential_access","sev": "high",   "mitre": "T1555",   "desc": "Password retrieval function"},
    {"s": "CredEnumerate",        "cat": "credential_access","sev": "high",   "mitre": "T1555.004","desc": "Credential manager enumeration"},

    # ── Lateral Movement ─────────────────────────────────────────────────────
    {"s": "psexec",               "cat": "lateral_movement","sev": "critical","mitre": "T1021.002","desc": "PsExec remote execution"},
    {"s": "PsExec.exe",           "cat": "lateral_movement","sev": "critical","mitre": "T1021.002","desc": "PsExec binary"},
    {"s": "net use",              "cat": "lateral_movement","sev": "high",   "mitre": "T1021.002","desc": "SMB share connection"},
    {"s": "net view",             "cat": "lateral_movement","sev": "medium", "mitre": "T1135",   "desc": "Network share enumeration"},
    {"s": "WNetAddConnection",    "cat": "lateral_movement","sev": "high",   "mitre": "T1021.002","desc": "Network connection API"},
    {"s": "ImpersonateLoggedOnUser","cat":"lateral_movement","sev": "high",  "mitre": "T1134",   "desc": "Token impersonation"},
    {"s": "CreateProcessWithToken","cat":"lateral_movement", "sev": "high",  "mitre": "T1134.002","desc": "Process creation with token"},
    {"s": "SMB",                  "cat": "lateral_movement","sev": "medium", "mitre": "T1021.002","desc": "SMB protocol reference"},
    {"s": "RDP",                  "cat": "lateral_movement","sev": "medium", "mitre": "T1021.001","desc": "RDP reference"},
    {"s": "mstsc",                "cat": "lateral_movement","sev": "medium", "mitre": "T1021.001","desc": "RDP client"},
    {"s": "WinRM",                "cat": "lateral_movement","sev": "high",   "mitre": "T1021.006","desc": "WinRM remote management"},
    {"s": "Enter-PSSession",      "cat": "lateral_movement","sev": "high",   "mitre": "T1021.006","desc": "PowerShell remote session"},

    # ── Defense Evasion ───────────────────────────────────────────────────────
    {"s": "AmsiScanBuffer",       "cat": "defense_evasion","sev": "critical","mitre": "T1562.001","desc": "AMSI bypass target"},
    {"s": "amsi.dll",             "cat": "defense_evasion","sev": "critical","mitre": "T1562.001","desc": "AMSI DLL reference"},
    {"s": "Set-MpPreference",     "cat": "defense_evasion","sev": "critical","mitre": "T1562.001","desc": "Disable Windows Defender"},
    {"s": "DisableRealtimeMonitoring","cat":"defense_evasion","sev":"critical","mitre":"T1562.001","desc": "Disable AV realtime"},
    {"s": "netsh advfirewall",    "cat": "defense_evasion","sev": "high",   "mitre": "T1562.004","desc": "Firewall rule modification"},
    {"s": "bcdedit",              "cat": "defense_evasion","sev": "high",   "mitre": "T1490",   "desc": "Boot config modification"},
    {"s": "vssadmin",             "cat": "defense_evasion","sev": "critical","mitre": "T1490",   "desc": "Shadow copy deletion"},
    {"s": "wbadmin",              "cat": "defense_evasion","sev": "high",   "mitre": "T1490",   "desc": "Backup deletion"},
    {"s": "wevtutil",             "cat": "defense_evasion","sev": "high",   "mitre": "T1070.001","desc": "Event log clearing"},
    {"s": "Clear-EventLog",       "cat": "defense_evasion","sev": "high",   "mitre": "T1070.001","desc": "PowerShell log clearing"},
    {"s": "del /f",               "cat": "defense_evasion","sev": "medium", "mitre": "T1070.004","desc": "Forced file deletion"},
    {"s": "SuspendThread",        "cat": "defense_evasion","sev": "high",   "mitre": "T1055",   "desc": "Thread suspension (injection)"},
    {"s": "NtUnmapViewOfSection", "cat": "defense_evasion","sev": "critical","mitre": "T1055.012","desc": "Process hollowing API"},
    {"s": "SetThreadContext",     "cat": "defense_evasion","sev": "high",   "mitre": "T1055",   "desc": "Thread context modification"},
    {"s": "obfusc",               "cat": "defense_evasion","sev": "medium", "mitre": "T1027",   "desc": "Obfuscation reference"},
    {"s": "-EncodedCommand",      "cat": "defense_evasion","sev": "critical","mitre": "T1027",   "desc": "PowerShell encoded command"},
    {"s": "-enc",                 "cat": "defense_evasion","sev": "high",   "mitre": "T1027",   "desc": "PowerShell -enc flag"},
    {"s": "frombase64string",     "cat": "defense_evasion","sev": "high",   "mitre": "T1140",   "desc": "Base64 decode"},
    {"s": "FromBase64String",     "cat": "defense_evasion","sev": "high",   "mitre": "T1140",   "desc": "Base64 decode .NET"},

    # ── Persistence ───────────────────────────────────────────────────────────
    {"s": "CurrentVersion\\Run",  "cat": "persistence",    "sev": "high",   "mitre": "T1547.001","desc": "Registry Run key"},
    {"s": "CurrentVersion\\RunOnce","cat":"persistence",   "sev": "high",   "mitre": "T1547.001","desc": "Registry RunOnce key"},
    {"s": "schtasks",             "cat": "persistence",    "sev": "high",   "mitre": "T1053.005","desc": "Scheduled task creation"},
    {"s": "at.exe",               "cat": "persistence",    "sev": "high",   "mitre": "T1053.002","desc": "AT job scheduler"},
    {"s": "sc create",            "cat": "persistence",    "sev": "high",   "mitre": "T1543.003","desc": "Service creation"},
    {"s": "sc config",            "cat": "persistence",    "sev": "high",   "mitre": "T1543.003","desc": "Service configuration"},
    {"s": "New-Service",          "cat": "persistence",    "sev": "high",   "mitre": "T1543.003","desc": "PowerShell service creation"},
    {"s": "Startup",              "cat": "persistence",    "sev": "medium", "mitre": "T1547.001","desc": "Startup folder reference"},
    {"s": "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                                  "cat": "persistence",    "sev": "critical","mitre": "T1547.004","desc": "Winlogon hijack"},
    {"s": "AppInit_DLLs",         "cat": "persistence",    "sev": "critical","mitre": "T1546.010","desc": "AppInit DLL persistence"},
    {"s": "Image File Execution Options","cat":"persistence","sev":"critical","mitre":"T1546.012","desc": "IFEO debugger hijack"},

    # ── Reconnaissance ────────────────────────────────────────────────────────
    {"s": "ipconfig",             "cat": "reconnaissance", "sev": "low",    "mitre": "T1016",   "desc": "Network config enumeration"},
    {"s": "whoami",               "cat": "reconnaissance", "sev": "low",    "mitre": "T1033",   "desc": "User identity query"},
    {"s": "systeminfo",           "cat": "reconnaissance", "sev": "medium", "mitre": "T1082",   "desc": "System info enumeration"},
    {"s": "net user",             "cat": "reconnaissance", "sev": "medium", "mitre": "T1087",   "desc": "User account enumeration"},
    {"s": "net localgroup",       "cat": "reconnaissance", "sev": "medium", "mitre": "T1069",   "desc": "Local group enumeration"},
    {"s": "nltest",               "cat": "reconnaissance", "sev": "medium", "mitre": "T1482",   "desc": "Domain trust enumeration"},
    {"s": "tasklist",             "cat": "reconnaissance", "sev": "low",    "mitre": "T1057",   "desc": "Process listing"},
    {"s": "netstat",              "cat": "reconnaissance", "sev": "low",    "mitre": "T1049",   "desc": "Network connections"},
    {"s": "arp -a",               "cat": "reconnaissance", "sev": "low",    "mitre": "T1018",   "desc": "ARP table enumeration"},
    {"s": "nslookup",             "cat": "reconnaissance", "sev": "low",    "mitre": "T1018",   "desc": "DNS lookup"},
    {"s": "GetComputerName",      "cat": "reconnaissance", "sev": "low",    "mitre": "T1082",   "desc": "Computer name API"},
    {"s": "GetUserName",          "cat": "reconnaissance", "sev": "low",    "mitre": "T1033",   "desc": "Username API"},
    {"s": "EnumProcesses",        "cat": "reconnaissance", "sev": "medium", "mitre": "T1057",   "desc": "Process enumeration API"},
    {"s": "CreateToolhelp32Snapshot","cat":"reconnaissance","sev": "medium","mitre": "T1057",   "desc": "Process snapshot API"},

    # ── Ransomware ────────────────────────────────────────────────────────────
    {"s": "CryptEncrypt",         "cat": "ransomware",     "sev": "critical","mitre": "T1486",   "desc": "File encryption API"},
    {"s": "CryptGenKey",          "cat": "ransomware",     "sev": "critical","mitre": "T1486",   "desc": "Key generation API"},
    {"s": "CryptImportKey",       "cat": "ransomware",     "sev": "critical","mitre": "T1486",   "desc": "Key import API"},
    {"s": "YOUR FILES",           "cat": "ransomware",     "sev": "critical","mitre": "T1486",   "desc": "Ransom note pattern"},
    {"s": "bitcoin",              "cat": "ransomware",     "sev": "critical","mitre": "T1486",   "desc": "Bitcoin payment demand"},
    {"s": "ransom",               "cat": "ransomware",     "sev": "critical","mitre": "T1486",   "desc": "Ransom string"},
    {"s": ".locked",              "cat": "ransomware",     "sev": "high",   "mitre": "T1486",   "desc": "Encrypted file extension"},
    {"s": ".encrypted",           "cat": "ransomware",     "sev": "high",   "mitre": "T1486",   "desc": "Encrypted file extension"},
    {"s": "decrypt",              "cat": "ransomware",     "sev": "high",   "mitre": "T1486",   "desc": "Decryption reference"},
    {"s": "wallet",               "cat": "ransomware",     "sev": "high",   "mitre": "T1486",   "desc": "Crypto wallet reference"},

    # ── Injection / Process Manipulation ─────────────────────────────────────
    {"s": "VirtualAllocEx",       "cat": "injection",      "sev": "critical","mitre": "T1055",   "desc": "Remote memory allocation"},
    {"s": "WriteProcessMemory",   "cat": "injection",      "sev": "critical","mitre": "T1055",   "desc": "Process memory write"},
    {"s": "CreateRemoteThread",   "cat": "injection",      "sev": "critical","mitre": "T1055.003","desc": "Remote thread injection"},
    {"s": "QueueUserAPC",         "cat": "injection",      "sev": "critical","mitre": "T1055.004","desc": "APC injection"},
    {"s": "NtCreateSection",      "cat": "injection",      "sev": "high",   "mitre": "T1055",   "desc": "Section object for injection"},
    {"s": "MapViewOfSection",     "cat": "injection",      "sev": "high",   "mitre": "T1055",   "desc": "Memory mapping injection"},
    {"s": "OpenProcess",          "cat": "injection",      "sev": "medium", "mitre": "T1055",   "desc": "Process handle acquisition"},

    # ── C2 / Network ─────────────────────────────────────────────────────────
    {"s": "InternetOpenUrl",      "cat": "c2_network",     "sev": "high",   "mitre": "T1071.001","desc": "HTTP C2 communication"},
    {"s": "HttpSendRequest",      "cat": "c2_network",     "sev": "high",   "mitre": "T1071.001","desc": "HTTP request API"},
    {"s": "WSAStartup",           "cat": "c2_network",     "sev": "medium", "mitre": "T1095",   "desc": "Winsock initialization"},
    {"s": "connect",              "cat": "c2_network",     "sev": "low",    "mitre": "T1095",   "desc": "Socket connect"},
    {"s": "send",                 "cat": "c2_network",     "sev": "low",    "mitre": "T1041",   "desc": "Socket send"},
    {"s": "recv",                 "cat": "c2_network",     "sev": "low",    "mitre": "T1041",   "desc": "Socket receive"},
    {"s": "irc",                  "cat": "c2_network",     "sev": "medium", "mitre": "T1071.003","desc": "IRC C2 channel"},
    {"s": "tor",                  "cat": "c2_network",     "sev": "high",   "mitre": "T1090.003","desc": "Tor anonymization"},
    {"s": ".onion",               "cat": "c2_network",     "sev": "critical","mitre": "T1090.003","desc": "Tor hidden service"},
    {"s": "socks5",               "cat": "c2_network",     "sev": "high",   "mitre": "T1090",   "desc": "SOCKS5 proxy"},
    {"s": "ngrok",                "cat": "c2_network",     "sev": "high",   "mitre": "T1572",   "desc": "Ngrok tunneling"},
    {"s": "cobalt strike",        "cat": "c2_network",     "sev": "critical","mitre": "T1071",   "desc": "Cobalt Strike C2 framework"},
    {"s": "beacon",               "cat": "c2_network",     "sev": "high",   "mitre": "T1071",   "desc": "Cobalt Strike beacon"},
    {"s": "metasploit",           "cat": "c2_network",     "sev": "critical","mitre": "T1071",   "desc": "Metasploit framework"},
    {"s": "meterpreter",          "cat": "c2_network",     "sev": "critical","mitre": "T1071",   "desc": "Meterpreter payload"},

    # ── Anti-Analysis ─────────────────────────────────────────────────────────
    {"s": "IsDebuggerPresent",    "cat": "anti_analysis",  "sev": "medium", "mitre": "T1622",   "desc": "Debugger detection"},
    {"s": "CheckRemoteDebuggerPresent","cat":"anti_analysis","sev":"medium", "mitre": "T1622",   "desc": "Remote debugger check"},
    {"s": "NtQueryInformationProcess","cat":"anti_analysis","sev": "medium","mitre": "T1622",   "desc": "Process info query (anti-debug)"},
    {"s": "GetTickCount",         "cat": "anti_analysis",  "sev": "low",    "mitre": "T1497",   "desc": "Timing-based sandbox evasion"},
    {"s": "Sleep",                "cat": "anti_analysis",  "sev": "low",    "mitre": "T1497",   "desc": "Sleep for sandbox evasion"},
    {"s": "VirtualBox",           "cat": "anti_analysis",  "sev": "medium", "mitre": "T1497.001","desc": "VM detection string"},
    {"s": "VMware",               "cat": "anti_analysis",  "sev": "medium", "mitre": "T1497.001","desc": "VMware detection string"},
    {"s": "VBOX",                 "cat": "anti_analysis",  "sev": "medium", "mitre": "T1497.001","desc": "VirtualBox detection"},
    {"s": "QEMU",                 "cat": "anti_analysis",  "sev": "medium", "mitre": "T1497.001","desc": "QEMU VM detection"},
    {"s": "sandbox",              "cat": "anti_analysis",  "sev": "medium", "mitre": "T1497",   "desc": "Sandbox reference"},
    {"s": "Wireshark",            "cat": "anti_analysis",  "sev": "medium", "mitre": "T1622",   "desc": "Analysis tool detection"},
    {"s": "OllyDbg",              "cat": "anti_analysis",  "sev": "medium", "mitre": "T1622",   "desc": "Debugger detection"},
    {"s": "x64dbg",               "cat": "anti_analysis",  "sev": "medium", "mitre": "T1622",   "desc": "Debugger detection"},
    {"s": "IDA",                  "cat": "anti_analysis",  "sev": "low",    "mitre": "T1622",   "desc": "Disassembler reference"},

    # ── Keylogger / Spyware ───────────────────────────────────────────────────
    {"s": "SetWindowsHookEx",     "cat": "keylogger",      "sev": "high",   "mitre": "T1056.001","desc": "Keyboard hook installation"},
    {"s": "GetAsyncKeyState",     "cat": "keylogger",      "sev": "high",   "mitre": "T1056.001","desc": "Async key state polling"},
    {"s": "GetKeyState",          "cat": "keylogger",      "sev": "medium", "mitre": "T1056.001","desc": "Key state API"},
    {"s": "GetForegroundWindow",  "cat": "keylogger",      "sev": "medium", "mitre": "T1056",   "desc": "Active window tracking"},
    {"s": "GetClipboardData",     "cat": "keylogger",      "sev": "high",   "mitre": "T1115",   "desc": "Clipboard theft"},
    {"s": "SetClipboardData",     "cat": "keylogger",      "sev": "medium", "mitre": "T1115",   "desc": "Clipboard manipulation"},
    {"s": "screenshot",           "cat": "keylogger",      "sev": "medium", "mitre": "T1113",   "desc": "Screenshot capture"},
    {"s": "BitBlt",               "cat": "keylogger",      "sev": "medium", "mitre": "T1113",   "desc": "Screen capture API"},

    # ── Privilege Escalation ──────────────────────────────────────────────────
    {"s": "SeDebugPrivilege",     "cat": "privilege_esc",  "sev": "high",   "mitre": "T1134",   "desc": "Debug privilege request"},
    {"s": "AdjustTokenPrivileges","cat": "privilege_esc",  "sev": "high",   "mitre": "T1134",   "desc": "Token privilege adjustment"},
    {"s": "LookupPrivilegeValue", "cat": "privilege_esc",  "sev": "medium", "mitre": "T1134",   "desc": "Privilege value lookup"},
    {"s": "IsUserAnAdmin",        "cat": "privilege_esc",  "sev": "medium", "mitre": "T1548",   "desc": "Admin check"},
    {"s": "runas",                "cat": "privilege_esc",  "sev": "medium", "mitre": "T1548",   "desc": "Run as admin"},
    {"s": "UAC",                  "cat": "privilege_esc",  "sev": "medium", "mitre": "T1548.002","desc": "UAC bypass reference"},
    {"s": "eventvwr",             "cat": "privilege_esc",  "sev": "high",   "mitre": "T1548.002","desc": "EventVwr UAC bypass"},
    {"s": "fodhelper",            "cat": "privilege_esc",  "sev": "high",   "mitre": "T1548.002","desc": "Fodhelper UAC bypass"},
    {"s": "cmstp",                "cat": "privilege_esc",  "sev": "high",   "mitre": "T1548.002","desc": "CMSTP UAC bypass"},
]


# ═════════════════════════════════════════════════════════════════════════════
#  2. REGEX DYNAMIQUES
#  Couvrent les patterns impossibles à lister statiquement
# ═════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_REGEX: List[Dict] = [
    {
        "pattern": re.compile(r"powershell\s+-[Ee][Nn][Cc](?:[Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd])?\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE),
        "cat": "defense_evasion", "sev": "critical", "mitre": "T1027",
        "desc": "PowerShell encoded command (base64)"
    },
    {
        "pattern": re.compile(r"(?:cmd|powershell)\s+/[cC]\s+.{10,}"),
        "cat": "execution", "sev": "high", "mitre": "T1059.003",
        "desc": "Inline command execution via cmd/powershell"
    },
    {
        "pattern": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),   # Long base64 block
        "cat": "defense_evasion", "sev": "medium", "mitre": "T1140",
        "desc": "Suspicious base64-encoded block"
    },
    {
        "pattern": re.compile(r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/\S*)?"),
        "cat": "c2_network", "sev": "high", "mitre": "T1071.001",
        "desc": "HTTP URL pointing to raw IP address (no domain)"
    },
    {
        "pattern": re.compile(r"\\\\[A-Za-z0-9._-]+\\[A-Za-z$][A-Za-z0-9_$-]*\\"),
        "cat": "lateral_movement", "sev": "medium", "mitre": "T1021.002",
        "desc": "UNC path — potential remote share access"
    },
    {
        "pattern": re.compile(r"(?:HKEY_LOCAL_MACHINE|HKLM|HKCU|HKEY_CURRENT_USER)\\[^\s]{10,}", re.IGNORECASE),
        "cat": "persistence", "sev": "medium", "mitre": "T1547",
        "desc": "Registry key path"
    },
    {
        "pattern": re.compile(r"(?:schtasks|at)\s+/create\s+.{5,}", re.IGNORECASE),
        "cat": "persistence", "sev": "high", "mitre": "T1053.005",
        "desc": "Scheduled task creation command"
    },
    {
        "pattern": re.compile(r"certutil\s+-(?:decode|urlcache|f)\s+\S+", re.IGNORECASE),
        "cat": "execution", "sev": "critical", "mitre": "T1140",
        "desc": "CertUtil used for decode/download"
    },
    {
        "pattern": re.compile(r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        "cat": "c2_network", "sev": "low", "mitre": "T1071",
        "desc": "Raw IP address"
    },
    {
        "pattern": re.compile(r"(?:tor2web|\.onion)", re.IGNORECASE),
        "cat": "c2_network", "sev": "critical", "mitre": "T1090.003",
        "desc": "Tor network reference"
    },
    {
        "pattern": re.compile(r"vssadmin\s+(?:delete|resize)\s+shadows", re.IGNORECASE),
        "cat": "defense_evasion", "sev": "critical", "mitre": "T1490",
        "desc": "Shadow copy deletion (ransomware pattern)"
    },
    {
        "pattern": re.compile(r"wmic\s+(?:shadowcopy|process|service)\s+\S+", re.IGNORECASE),
        "cat": "execution", "sev": "high", "mitre": "T1047",
        "desc": "WMIC command execution"
    },
]


# ═════════════════════════════════════════════════════════════════════════════
#  3. MOTEUR DE RECHERCHE
# ═════════════════════════════════════════════════════════════════════════════

def analyze_strings(strings_list: list) -> Dict:
    """
    Analyse une liste de strings extraites d'un binaire.
    Retourne un dictionnaire structuré par catégorie + liste complète des matches.
    """
    matches:   List[SuspiciousMatch] = []
    seen_strs: set = set()

    # ── Keyword scan ─────────────────────────────────────────────────────────
    for entry in SUSPICIOUS_KEYWORDS:
        needle = entry["s"].lower()
        for s in strings_list:
            if needle in s.lower() and s not in seen_strs:
                seen_strs.add(s)
                matches.append(SuspiciousMatch(
                    string      = s,
                    category    = entry["cat"],
                    description = entry["desc"],
                    severity    = entry["sev"],
                    mitre       = entry.get("mitre", ""),
                    match_type  = "keyword",
                ))

    # ── Regex scan ────────────────────────────────────────────────────────────
    for entry in SUSPICIOUS_REGEX:
        for s in strings_list:
            if s not in seen_strs and entry["pattern"].search(s):
                seen_strs.add(s)
                matches.append(SuspiciousMatch(
                    string      = s,
                    category    = entry["cat"],
                    description = entry["desc"],
                    severity    = entry["sev"],
                    mitre       = entry.get("mitre", ""),
                    match_type  = "regex",
                ))

    # ── Grouper par catégorie ─────────────────────────────────────────────────
    by_category: Dict[str, list] = {}
    for m in matches:
        by_category.setdefault(m.category, []).append({
            "string":      m.string[:200],   # Tronque pour éviter les strings géantes
            "description": m.description,
            "severity":    m.severity,
            "mitre":       m.mitre,
            "match_type":  m.match_type,
        })

    # ── Extraire URLs / IPs / Commands (compat avec l'ancien format) ──────────
    urls     = [m.string for m in matches if m.category == "c2_network"
                and m.string.startswith("http")][:10]
    ips      = [m.string for m in matches if m.category == "c2_network"
                and re.match(r"\d+\.\d+\.\d+\.\d+", m.string)][:10]
    commands = [m.string for m in matches if m.category in ("execution", "download")][:10]

    return {
        "by_category":     by_category,
        "urls":            urls,
        "ips":             ips,
        "commands":        commands,
        "total_matches":   len(matches),
        "all_matches":     [
            {
                "string":      m.string[:200],
                "category":    m.category,
                "description": m.description,
                "severity":    m.severity,
                "mitre":       m.mitre,
            }
            for m in matches
        ],
    }