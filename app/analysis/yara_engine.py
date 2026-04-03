"""
app/analysis/yara_engine.py — Règles YARA centralisées.
"""

YARA_RULES_SOURCE = r"""
rule Ransomware_Indicators {
    meta:
        description = "Detects ransomware-like behavior via string patterns"
        author      = "StaticAnalyzer"
        severity    = "critical"
        mitre       = "T1486"
    strings:
        $r1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $r2 = "bitcoin" nocase
        $r3 = "ransom" nocase
        $r4 = ".locked" nocase
        $r5 = "decrypt" nocase
        $r6 = "CryptEncrypt" nocase
        $r7 = "CryptGenKey" nocase
    condition:
        2 of them
}

rule Shellcode_Indicators {
    meta:
        description = "Detects common shellcode patterns"
        author      = "StaticAnalyzer"
        severity    = "high"
        mitre       = "T1055"
    strings:
        $s1 = { 60 89 E5 31 C0 64 8B 50 30 }
        $s2 = { FC E8 82 00 00 00 60 }
        $s3 = "VirtualAlloc" nocase
        $s4 = "VirtualProtect" nocase
        $s5 = "WriteProcessMemory" nocase
    condition:
        any of them
}

rule Network_Exfil_Indicators {
    meta:
        description = "Detects potential data exfiltration or C2 communication"
        author      = "StaticAnalyzer"
        severity    = "high"
        mitre       = "T1041"
    strings:
        $n1 = "InternetOpenUrl" nocase
        $n2 = "HttpSendRequest" nocase
        $n3 = "WSAStartup" nocase
        $n4 = "connect" nocase
        $n5 = "send" nocase
        $n6 = "recv" nocase
    condition:
        3 of them
}

rule Persistence_Mechanisms {
    meta:
        description = "Detects registry-based persistence or scheduled tasks"
        author      = "StaticAnalyzer"
        severity    = "medium"
        mitre       = "T1547"
    strings:
        $p1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $p2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $p3 = "schtasks" nocase
        $p4 = "RegSetValueEx" nocase
        $p5 = "sc create" nocase
    condition:
        any of them
}

rule Privilege_Escalation {
    meta:
        description = "Detects privilege escalation attempts"
        author      = "StaticAnalyzer"
        severity    = "high"
        mitre       = "T1548"
    strings:
        $e1 = "SeDebugPrivilege" nocase
        $e2 = "AdjustTokenPrivileges" nocase
        $e3 = "OpenProcessToken" nocase
        $e4 = "LookupPrivilegeValue" nocase
        $e5 = "IsUserAnAdmin" nocase
        $e6 = "runas" nocase
    condition:
        2 of them
}

rule Packer_Indicators {
    meta:
        description = "Detects common binary packers (UPX, MPRESS, etc.)"
        author      = "StaticAnalyzer"
        severity    = "medium"
        mitre       = "T1027"
    strings:
        $u1 = "UPX0" nocase
        $u2 = "UPX1" nocase
        $u3 = "MPRESS1" nocase
        $u4 = "PECompact" nocase
        $u5 = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF }
    condition:
        any of them
}

rule Keylogger_Indicators {
    meta:
        description = "Detects keylogger-like API usage"
        author      = "StaticAnalyzer"
        severity    = "high"
        mitre       = "T1056"
    strings:
        $k1 = "SetWindowsHookEx" nocase
        $k2 = "GetAsyncKeyState" nocase
        $k3 = "GetForegroundWindow" nocase
        $k4 = "GetKeyState" nocase
    condition:
        2 of them
}

rule Anti_Debug_Techniques {
    meta:
        description = "Detects common anti-debugging techniques"
        author      = "StaticAnalyzer"
        severity    = "medium"
        mitre       = "T1622"
    strings:
        $d1 = "IsDebuggerPresent" nocase
        $d2 = "CheckRemoteDebuggerPresent" nocase
        $d3 = "NtQueryInformationProcess" nocase
        $d4 = "OutputDebugString" nocase
        $d5 = "FindWindow" nocase
    condition:
        2 of them
}

rule Document_Macro_Suspicious {
    meta:
        description = "Detects suspicious macro patterns in Office documents"
        author      = "StaticAnalyzer"
        severity    = "high"
        mitre       = "T1137"
    strings:
        $m1 = "AutoOpen" nocase
        $m2 = "Document_Open" nocase
        $m3 = "Shell" nocase
        $m4 = "WScript.Shell" nocase
        $m5 = "CreateObject" nocase
        $m6 = "powershell" nocase
    condition:
        2 of them
}

rule PDF_Suspicious {
    meta:
        description = "Detects suspicious elements in PDF files"
        author      = "StaticAnalyzer"
        severity    = "high"
        mitre       = "T1204"
    strings:
        $p1 = "/JavaScript" nocase
        $p2 = "/Launch" nocase
        $p3 = "/OpenAction" nocase
        $p4 = "/EmbeddedFile" nocase
        $p5 = "/RichMedia" nocase
    condition:
        any of them
}
"""