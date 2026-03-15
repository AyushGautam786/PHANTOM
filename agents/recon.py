import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.nmap_tool import run_nmap
from tools.shodan_tool import query_shodan
from memory.store import PhantomMemory

class ReconAgent:
    def __init__(self, memory: PhantomMemory):
        self.memory = memory
        self.name = "recon"

    def run(self, target: str, target_path: str = None) -> dict:
        print(f"\n[RECON] Starting surface mapping on {target}")

        shodan_data = {}
        shodan_key = os.getenv("SHODAN_API_KEY")
        if shodan_key and shodan_key != "your_key_here":
            print("[RECON] Querying Shodan (passive)...")
            shodan_data = query_shodan(target)
        else:
            print("[RECON] Shodan key not set — skipping passive recon")

        print(f"[RECON] Running nmap on {target}...")
        nmap_data = run_nmap(target)

        code_surface = {}
        if target_path and os.path.exists(target_path):
            print(f"[RECON] Scanning codebase at {target_path}...")
            code_surface = self._scan_codebase(target_path)

        attack_surface = {
            "target":          target,
            "target_path":     target_path,
            "network_surface": nmap_data,
            "passive_intel":   shodan_data,
            "code_surface":    code_surface,
        }

        self.memory.store(self.name, "attack_surface", attack_surface, "COMPLETE")
        print(f"[RECON] Found {len(nmap_data.get('open_ports', []))} open ports")
        return attack_surface

    def _scan_codebase(self, path: str) -> dict:
        import glob, re
        py_files = glob.glob(f"{path}/**/*.py", recursive=True)
        has_requirements = os.path.exists(f"{path}/requirements.txt")
        has_env = os.path.exists(f"{path}/.env")
        has_debug = False
        entry_points = []
        for fpath in py_files:
            try:
                content = open(fpath).read()
                if "DEBUG = True" in content or "debug=True" in content:
                    has_debug = True
                if "@app.route" in content:
                    routes = re.findall(r'@app\.route\(["\']([^"\']+)', content)
                    for r in routes:
                        entry_points.append({"route": r, "file": fpath})
            except Exception:
                pass
        deps = []
        if has_requirements:
            try:
                deps = open(f"{path}/requirements.txt").read().strip().split("\n")
            except Exception:
                pass
        return {
            "python_files": py_files,
            "entry_points": entry_points,
            "dependencies": deps,
            "has_debug":    has_debug,
            "has_dotenv":   has_env,
            "file_count":   len(py_files)
        }
