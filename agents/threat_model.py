from tools.mitre_tool import map_to_attack
from tools.nvd_tool import search_cves_by_keyword
from memory.store import PhantomMemory

class ThreatModelAgent:
    def __init__(self, memory: PhantomMemory):
        self.memory = memory
        self.name = "threat_model"

    def run(self, attack_surface: dict) -> dict:
        print("\n[THREAT MODEL] Classifying attack surface via MITRE ATT&CK...")
        findings = []

        for port_info in attack_surface.get("network_surface", {}).get("open_ports", []):
            service = port_info.get("service", "unknown")
            attack_mapping = map_to_attack(service)
            finding = {
                "source":         "network",
                "service":        service,
                "port":           port_info["port"],
                "version":        port_info.get("version", ""),
                "attack_tactic":  attack_mapping["tactic"],
                "technique_id":   attack_mapping["technique_id"],
                "technique_name": attack_mapping["technique_name"],
                "stride":         attack_mapping["stride"],
                "kill_chain_pos": self._kill_chain_depth(attack_mapping["tactic"]),
                "priority":       self._calc_priority(port_info, attack_mapping)
            }
            if port_info.get("product") or service != "unknown":
                keyword = f"{port_info.get('product', service)} {port_info.get('version', '')}".strip()
                known_cves = search_cves_by_keyword(keyword)
                finding["known_cves"] = known_cves[:2]
            findings.append(finding)
            print(f"[THREAT MODEL] {service}:{port_info['port']} -> "
                  f"{attack_mapping['technique_id']} ({attack_mapping['tactic']})")

        code_surface = attack_surface.get("code_surface", {})
        if code_surface.get("has_debug"):
            debug_mapping = map_to_attack("debug_enabled")
            findings.append({
                "source":        "code",
                "type":          "DEBUG_ENABLED",
                "attack_tactic": debug_mapping["tactic"],
                "technique_id":  debug_mapping["technique_id"],
                "stride":        debug_mapping["stride"],
                "priority":      2,
                "kill_chain_pos": 2
            })

        findings.sort(key=lambda x: x.get("priority", 99))
        threat_model = {
            "findings":           findings,
            "highest_risk":       findings[0] if findings else None,
            "total_attack_paths": len(findings)
        }
        self.memory.store(self.name, "threat_model", threat_model, "COMPLETE")
        print(f"[THREAT MODEL] Identified {len(findings)} attack paths")
        return threat_model

    def _kill_chain_depth(self, tactic: str) -> int:
        order = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact"
        ]
        try:
            return order.index(tactic) + 1
        except ValueError:
            return 7

    def _calc_priority(self, port_info: dict, attack_mapping: dict) -> int:
        score = 5
        if port_info.get("port") in [80, 443, 8080, 8443]:
            score -= 2
        if port_info.get("port") in [5432, 3306, 27017, 6379]:
            score -= 1
        depth = self._kill_chain_depth(attack_mapping["tactic"])
        if depth <= 3:
            score -= 1
        return max(1, score)
