TECHNIQUE_MAP = {
    "postgresql":        ("Initial Access",    "T1190",      "Exploit Public-Facing Application"),
    "mysql":             ("Initial Access",    "T1190",      "Exploit Public-Facing Application"),
    "ssh":               ("Lateral Movement",  "T1021.004",  "SSH"),
    "http":              ("Reconnaissance",    "T1592",      "Gather Victim Host Information"),
    "ssti":              ("Execution",         "T1059.006",  "Command and Scripting: Python"),
    "sqli":              ("Execution",         "T1059",      "Command and Scripting Interpreter"),
    "rce":               ("Execution",         "T1203",      "Exploitation for Client Execution"),
    "path_traversal":    ("Collection",        "T1083",      "File and Directory Discovery"),
    "xss":               ("Collection",        "T1185",      "Browser Session Hijacking"),
    "command_injection": ("Execution",         "T1059",      "Command and Scripting Interpreter"),
    "hardcoded_secret":  ("Credential Access", "T1552",      "Unsecured Credentials"),
    "debug_enabled":     ("Discovery",         "T1082",      "System Information Discovery"),
}

STRIDE_MAP = {
    "T1190":     ["Elevation of Privilege", "Information Disclosure"],
    "T1059.006": ["Tampering", "Information Disclosure"],
    "T1059":     ["Tampering", "Elevation of Privilege"],
    "T1552":     ["Information Disclosure"],
    "T1082":     ["Information Disclosure"],
    "T1083":     ["Information Disclosure"],
    "T1021.004": ["Lateral Movement", "Elevation of Privilege"],
}

def map_to_attack(service_or_vuln: str) -> dict:
    """Map a service name or vulnerability type to MITRE ATT&CK."""
    key = service_or_vuln.lower()
    if key in TECHNIQUE_MAP:
        tactic, tid, tname = TECHNIQUE_MAP[key]
        return {
            "tactic":         tactic,
            "technique_id":   tid,
            "technique_name": tname,
            "stride":         STRIDE_MAP.get(tid, ["Unknown"]),
            "matched_on":     key
        }
    for pattern, (tactic, tid, tname) in TECHNIQUE_MAP.items():
        if pattern in key or key in pattern:
            return {
                "tactic":         tactic,
                "technique_id":   tid,
                "technique_name": tname,
                "stride":         STRIDE_MAP.get(tid, ["Unknown"]),
                "matched_on":     pattern
            }
    return {
        "tactic":         "Unknown",
        "technique_id":   "T0000",
        "technique_name": "Unclassified",
        "stride":         ["Unknown"],
        "matched_on":     key
    }
