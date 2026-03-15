"""
PHANTOM - Single-command launcher with dependency checks.
Run: python run.py
"""
import sys
import os
import subprocess
import time

BASE = os.path.dirname(os.path.abspath(__file__))

def check_dependencies():
    missing = []
    required = {
        "google.genai":    "google-genai",
        "chromadb":        "chromadb",
        "dotenv":          "python-dotenv",
        "requests":        "requests",
        "flask":           "flask",
    }
    for module, package in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"[SETUP] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        print("[SETUP] Done. Re-launching...\n")
        os.execv(sys.executable, [sys.executable] + sys.argv)

def check_env():
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE, ".env"))
    key = os.getenv("GEMINI_API_KEY")
    if not key or key.strip() == "":
        print("\n[ERROR] GEMINI_API_KEY is not set in your .env file.")
        print(f"  Edit: {os.path.join(BASE, '.env')}")
        print("  Add:  GEMINI_API_KEY=your_key_here\n")
        sys.exit(1)
    print(f"[SETUP] Gemini key loaded ✓")

def start_target_app():
    app_path = os.path.join(BASE, "target_app", "app.py")
    print("[SETUP] Starting target Flask app on port 5000...")
    try:
        proc = subprocess.Popen(
            [sys.executable, app_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)  # wait for Flask to start
        # Check it actually started
        import socket
        s = socket.socket()
        s.settimeout(1)
        result = s.connect_ex(("127.0.0.1", 5000))
        s.close()
        if result == 0:
            print("[SETUP] Target app running at http://127.0.0.1:5000 ✓")
        else:
            print("[SETUP] Target app may not be running — continuing anyway")
        return proc
    except Exception as e:
        print(f"[SETUP] Could not start target app: {e}")
        return None

def main():
    print("\n" + "="*60)
    print("  PHANTOM - AI Pentesting System")
    print("="*60 + "\n")

    # Step 1: Check & install dependencies
    check_dependencies()

    # Step 2: Check API key
    check_env()

    # Step 3: Start target app
    proc = start_target_app()

    # Step 4: Run PHANTOM
    print("\n[SETUP] Launching PHANTOM scan...\n")
    try:
        sys.path.insert(0, BASE)
        from orchestrator import PhantomOrchestrator
        import json

        target_path = os.path.join(BASE, "target_app")
        orchestrator = PhantomOrchestrator()
        report = orchestrator.run("127.0.0.1", target_path)

        # Print report
        print("\n" + "="*60)
        print("PHANTOM ASSESSMENT REPORT")
        print("="*60)
        print(f"Session:  {report['session_id']}")
        print(f"Duration: {report.get('duration_seconds', 0):.1f}s")
        print(f"\n--- EXECUTIVE SUMMARY ---")
        print(report.get("executive_summary", "Not generated"))
        stats = report.get("stats", {})
        print(f"\n--- STATS ---")
        print(f"Confirmed findings:   {stats.get('confirmed_findings', 0)}")
        print(f"Unconfirmed findings: {stats.get('unconfirmed_findings', 0)}")
        print(f"Patches generated:    {stats.get('patches_generated', 0)}")
        print(f"\n--- CONFIRMED FINDINGS ---")
        for f in report.get("technical_findings", []):
            if f["status"] == "CONFIRMED":
                print(f"\n  [{f['id']}] {f['type']}")
                print(f"  File: {f['file']}:{f['line']}")
                print(f"  CVSS: {f.get('cvss', 0):.1f}  Technique: {f.get('technique_id','')}")
                print(f"  Confidence: {f.get('confidence', 0):.0%}")
        print(f"\n--- THOUGHT TRACE ---")
        for step in report.get("thought_trace", []):
            print(f"  [Cycle {step['cycle']}] {step['agent'].upper()}: {step['thought'][:80]}...")

        # Save JSON report
        out = os.path.join(BASE, f"phantom_report_{report['session_id']}.json")
        with open(out, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n✓ Full report saved: {out}\n")

    except Exception as e:
        import traceback
        print(f"\n[ERROR] PHANTOM failed: {e}")
        traceback.print_exc()
    finally:
        if proc:
            proc.terminate()
            print("[SETUP] Target app stopped.")

if __name__ == "__main__":
    main()
