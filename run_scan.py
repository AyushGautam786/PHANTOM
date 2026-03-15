import subprocess
import time
import os
import sys

os.chdir(r"F:\internship protal\ai hackathon\phantom")

# Step 1: Install dependencies
print("Step 1: Installing dependencies...")
result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"], 
                       capture_output=False, text=True)
if result.returncode != 0:
    print(f"Error installing dependencies: {result.returncode}")
    sys.exit(1)
print("Dependencies installed successfully!\n")

# Step 2: Start target app
print("Step 2: Starting target app...")
target_app_path = r"F:\internship protal\ai hackathon\phantom\target_app\app.py"
app_process = subprocess.Popen([sys.executable, target_app_path], 
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
print(f"Target app started with PID: {app_process.pid}\n")

# Step 3: Wait for app to start
print("Step 3: Waiting 5 seconds for app to initialize...")
time.sleep(5)
print("App ready!\n")

# Step 4: Run PHANTOM scan
print("Step 4: Running PHANTOM scan...")
print("=" * 70)
result = subprocess.run([sys.executable, "main.py", "127.0.0.1", "./target_app"],
                       capture_output=False, text=True)
print("=" * 70)
print(f"\nPHANTOM scan completed with return code: {result.returncode}\n")

# Cleanup
print("Terminating target app...")
app_process.terminate()
try:
    app_process.wait(timeout=5)
except subprocess.TimeoutExpired:
    app_process.kill()
print("Done!")
