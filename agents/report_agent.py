import json
import os
import datetime
import hashlib
from memory.store import PhantomMemory
from llm import generate

class ReportAgent:
    def __init__(self, memory: PhantomMemory):
        self.memory = memory
        self.name = "report_agent"

    def run(self, all_results: dict, session_id: str) -> dict:
        print("\n[REPORT AGENT] Generating structured assessment report...")
        exec_summary = self._generate_executive_summary(all_results)
        tech_findings = self._format_technical_findings(all_results)
        audit_trail = self._build_audit_trail(session_id, all_results)
        report = {
            "session_id":         session_id,
            "timestamp":          datetime.datetime.utcnow().isoformat(),
            "target":             all_results.get("recon", {}).get("target", "unknown"),
            "duration_seconds":   all_results.get("duration", 0),
            "executive_summary":  exec_summary,
            "technical_findings": tech_findings,
            "audit_trail":        audit_trail,
            "stats": {
                "confirmed_findings":   len(all_results.get("exploit", {}).get("confirmed", [])),
                "unconfirmed_findings": len(all_results.get("exploit", {}).get("unconfirmed", [])),
                "patches_generated":    len(all_results.get("patches", {}).get("patches", [])),
                "patches_cleared":      sum(
                    1 for p in all_results.get("patches", {}).get("patches", [])
                    if p.get("bandit_cleared")
                )
            }
        }
        self.memory.store(self.name, "final_report", report, "COMPLETE")
        print(f"[REPORT AGENT] Report complete — "
              f"{report['stats']['confirmed_findings']} confirmed findings, "
              f"{report['stats']['patches_generated']} patches generated")
        return report

    def _generate_executive_summary(self, results: dict) -> str:
        confirmed = results.get("exploit", {}).get("confirmed", [])
        patches = results.get("patches", {}).get("patches", [])
        highest_cvss = max((c.get("cvss_estimate", 0) for c in confirmed), default=0)
        severity = ("CRITICAL" if highest_cvss >= 9 else
                    "HIGH" if highest_cvss >= 7 else
                    "MEDIUM" if highest_cvss >= 4 else "LOW")
        prompt = f"""Write a 4-sentence executive summary for a security assessment.
Results:
- Confirmed vulnerabilities: {len(confirmed)}
- Highest CVSS score: {highest_cvss} ({severity})
- Patches generated: {len(patches)}
- Top finding: {confirmed[0].get('reasoning', 'see technical section')[:200] if confirmed else 'None confirmed'}
Write for a non-technical manager. No jargon. Be direct about risk. End with one clear action item."""
        return generate(prompt)

    def _format_technical_findings(self, results: dict) -> list:
        findings = []
        for i, confirmed in enumerate(results.get("exploit", {}).get("confirmed", []), 1):
            finding = confirmed.get("finding", {})
            patch = next(
                (p for p in results.get("patches", {}).get("patches", [])
                 if p.get("file") == finding.get("file")),
                None
            )
            findings.append({
                "id":            f"FINDING-{i:03d}",
                "type":          finding.get("type", "unknown"),
                "file":          finding.get("file", "unknown"),
                "line":          finding.get("line", 0),
                "cvss":          confirmed.get("cvss_estimate", 0),
                "technique_id":  confirmed.get("technique_id", ""),
                "confidence":    confirmed.get("confidence", 0),
                "reasoning":     confirmed.get("reasoning", ""),
                "attack_vector": confirmed.get("attack_vector", ""),
                "patch":         patch,
                "status":        "CONFIRMED"
            })
        for i, unconfirmed in enumerate(results.get("exploit", {}).get("unconfirmed", []), 1):
            finding = unconfirmed.get("finding", {})
            findings.append({
                "id":        f"UNCONFIRMED-{i:03d}",
                "type":      finding.get("type", "unknown"),
                "file":      finding.get("file", "unknown"),
                "reasoning": unconfirmed.get("reasoning", ""),
                "confidence": unconfirmed.get("confidence", 0),
                "status":    "UNCONFIRMED"
            })
        return findings

    def _build_audit_trail(self, session_id: str, results: dict) -> list:
        trail = []
        prev_hash = "genesis"
        events = [
            ("SESSION_START",     "orchestrator",   {}),
            ("RECON_COMPLETE",    "recon",          {
                "ports": len(results.get("recon", {})
                             .get("network_surface", {})
                             .get("open_ports", []))
            }),
            ("THREAT_MODEL",      "threat_model",   {
                "attack_paths": results.get("threat_model", {}).get("total_attack_paths", 0)
            }),
            ("EXPLOIT_COMPLETE",  "exploit_engine", {
                "confirmed": len(results.get("exploit", {}).get("confirmed", []))
            }),
            ("PATCHES_GENERATED", "patch_agent",    {
                "count": len(results.get("patches", {}).get("patches", []))
            }),
            ("REPORT_GENERATED",  "report_agent",   {"session": session_id}),
        ]
        for event_type, agent, data in events:
            ts = datetime.datetime.utcnow().isoformat()
            content = f"{event_type}{agent}{json.dumps(data)}{prev_hash}{ts}"
            entry_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
            trail.append({
                "timestamp": ts,
                "event":     event_type,
                "agent":     agent,
                "data":      data,
                "hash":      entry_hash,
                "prev_hash": prev_hash
            })
            prev_hash = entry_hash
        return trail
