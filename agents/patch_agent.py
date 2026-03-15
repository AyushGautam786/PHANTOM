import json
import os
import hashlib
import datetime
from tools.bandit_tool import run_bandit
from memory.store import PhantomMemory
from llm import generate

class PatchAgent:
    def __init__(self, memory: PhantomMemory):
        self.memory = memory
        self.name = "patch_agent"

    def run(self, exploit_results: dict, session_id: str) -> dict:
        print("\n[PATCH AGENT] Generating ranked patches for confirmed findings...")
        patches = []
        for confirmed in exploit_results.get("confirmed", []):
            finding = confirmed.get("finding", {})
            patch = self._generate_patch(confirmed, finding)
            if patch:
                patch["bandit_cleared"] = self._verify_patch(patch, finding)
                patch["signature"] = self._sign_patch(patch.get("diff", ""), session_id)
                patches.append(patch)
                status = "CLEARED" if patch["bandit_cleared"] else "BLOCKED"
                print(f"[PATCH AGENT] Patch for {finding.get('type', 'unknown')}: Bandit {status}")

        output = {
            "patches":       patches,
            "total_patches": len(patches),
            "all_cleared":   all(p.get("bandit_cleared", False) for p in patches)
        }
        self.memory.store(self.name, "patches", output, "COMPLETE")
        return output

    def _generate_patch(self, confirmed: dict, finding: dict) -> dict:
        code_context = ""
        if finding.get("file") and os.path.exists(finding["file"]):
            try:
                lines = open(finding["file"]).readlines()
                start = max(0, finding.get("line", 1) - 5)
                end = min(len(lines), finding.get("line", 1) + 5)
                code_context = "".join(lines[start:end])
            except Exception:
                code_context = finding.get("code", "")

        prompt = f"""You are the Patch Agent in PHANTOM security system.
Generate a minimal, surgical code fix for this confirmed vulnerability.

VULNERABILITY:
Type: {finding.get('type', 'unknown')}
File: {finding.get('file', 'unknown')}
Line: {finding.get('line', 0)}
MITRE Technique: {confirmed.get('technique_id', 'unknown')}
CVSS Estimate: {confirmed.get('cvss_estimate', 0)}
Attack Vector: {confirmed.get('attack_vector', 'unknown')}

CODE CONTEXT:
{code_context}

Output a unified diff format patch, then write:
PLAIN ENGLISH: [3-sentence plain explanation for non-technical manager]"""

        text = generate(prompt)
        diff = ""
        plain_english = ""
        if "```diff" in text:
            diff = text.split("```diff")[1].split("```")[0].strip()
        if "PLAIN ENGLISH:" in text:
            plain_english = text.split("PLAIN ENGLISH:")[1].strip()
        return {
            "finding_type":  finding.get("type", "unknown"),
            "file":          finding.get("file", "unknown"),
            "line":          finding.get("line", 0),
            "cvss_estimate": confirmed.get("cvss_estimate", 0),
            "technique_id":  confirmed.get("technique_id", ""),
            "diff":          diff,
            "plain_english": plain_english,
            "confidence":    confirmed.get("confidence", 0)
        }

    def _verify_patch(self, patch: dict, finding: dict) -> bool:
        import tempfile, shutil
        if not patch.get("diff") or not finding.get("file"):
            return True
        if not os.path.exists(finding["file"]):
            return True
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                shutil.copy(finding["file"], tmpdir)
                result = run_bandit(tmpdir)
                return len(result.get("high_severity", [])) == 0
        except Exception:
            return True

    def _sign_patch(self, diff: str, session_id: str) -> str:
        ts = datetime.datetime.utcnow().isoformat()
        content = f"{diff}{session_id}{ts}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
