import os
import subprocess
import sys
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
if BASE_DIR.name == "obfuscation-engine":
    AEGIS_DIR = BASE_DIR
else:
    AEGIS_DIR = BASE_DIR / "obfuscation-engine"

def print_header(title):
    print("\n" + "="*80)
    print(f" {title} ".center(80, "="))
    print("="*80)

def check_command(cmd):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def run_cmd(cmd, cwd=None):
    print(f"Executing: {' '.join(cmd)} in {cwd or '.'}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        print(f"[-] Error executing: {' '.join(cmd)}")
        return False
    return True

def main():
    print_header("🛡️ AegisStatic Auto-Setup Utility 🛡️")
    print("[*] Project: CS-471 Reverse Engineering & Vulnerability Assessment")

    # 1. System Requirements Check
    print("\n[*] Verifying system prerequisites...")
    if not check_command(["python3", "--version"]):
        print("[-] Python 3 is required but not found. Exiting.")
        sys.exit(1)
    print("[+] Python 3 detected.")

    # 2. Setup AegisStatic (Python virtual environment and requirements)
    if AEGIS_DIR.exists():
        print_header("Configuring AegisStatic Environment")
        venv_dir = AEGIS_DIR / ".venv"
        if not venv_dir.exists():
            print("[*] Creating Python Virtual Environment (.venv)...")
            run_cmd(["python3", "-m", "venv", ".venv"], cwd=AEGIS_DIR)
        
        # Determine pip executable path
        pip_path = venv_dir / "bin" / "pip" if os.name != "nt" else venv_dir / "Scripts" / "pip.exe"
        
        print("[*] Installing AegisStatic python dependencies from requirements.txt...")
        run_cmd([str(pip_path), "install", "-r", "requirements.txt"], cwd=AEGIS_DIR)
        print("[+] AegisStatic setup complete.")
    else:
        print(f"[-] AegisStatic directory not found at: {AEGIS_DIR}")
        print("[-] Please ensure this script is run from the directory containing 'obfuscation-engine'.")
        sys.exit(1)

    # 3. Success Summary
    print_header("🚀 Setup Complete - Access Details 🚀")
    print("Run the following commands to start AegisStatic:")
    print(f"\n   cd {AEGIS_DIR}")
    print("   source .venv/bin/activate")
    print("   streamlit run app.py")
    print("\n   Access URL: http://localhost:8501")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
