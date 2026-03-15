import json
import sys
import os
from dotenv import load_dotenv
from orchestrator import PhantomOrchestrator

load_dotenv()

def print_report(report: dict):
    print("\n" + "="*60)
    print("PHANTOM ASSESSMENT REPORT")
    print("="*60)
    print(f"Session: {report['session_id']}")
    print(f"Duration: {report.get('duration_seconds', 0):.1f}s")
    print(f"\n--- EXECUTIVE SUMMARY ---")
    print(report.get("executive_summary", "Not generated"))
    print(f"\n--- STATS ---")
    stats = report.get("stats", {})
    print(f"Confirmed findings:   {stats.get('confirmed_findings', 0)}")
    print(f"Unconfirmed findings: {stats.get('unconfirmed_findings', 0)}")
    print(f"Patches generated:    {stats.get('patches_generated', 0)}")
    print(f"Patches cleared:      {stats.get('patches_cleared', 0)}")
    print(f"\n--- CONFIRMED FINDINGS ---")
    for f in report.get("technical_findings", []):
        if f["status"] == "CONFIRMED":
            print(f"\n[{f['id']}] {f['type']}")
            print(f"  File: {f['file']}:{f['line']}")
            print(f"  CVSS: {f['cvss']:.1f}  Technique: {f['technique_id']}")
            print(f"  Confidence: {f['confidence']:.0%}")
            if f.get("patch"):
                cleared = "v" if f["patch"].get("bandit_cleared") else "x"
                print(f"  Patch: {cleared} Bandit-cleared | Signed: {f['patch'].get('signature', 'N/A')}")
    print(f"\n--- THOUGHT TRACE ---")
    for step in report.get("thought_trace", []):
        print(f"[Cycle {step['cycle']}] {step['agent'].upper()}: {step['thought'][:80]}...")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <target_ip> [codebase_path]")
        print("Example: python main.py 127.0.0.1 ./target_app")
        sys.exit(1)

    target = sys.argv[1]
    target_path = sys.argv[2] if len(sys.argv) > 2 else None

    orchestrator = PhantomOrchestrator()
    report = orchestrator.run(target, target_path)
    print_report(report)

    output_file = f"phantom_report_{report['session_id']}.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report saved: {output_file}")
