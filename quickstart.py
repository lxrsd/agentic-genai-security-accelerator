#!/usr/bin/env python3
"""Cross-platform quickstart launcher for the Agentic GenAI Security Accelerator.

Usage:
    python3 quickstart.py              # Setup + start dashboard
    python3 quickstart.py --setup-only # Setup only, do not start server
    python3 quickstart.py --install-prowler  # Install Prowler for connected AWS scans
"""

import os
import platform
import subprocess
import sys
from pathlib import Path


def main():
    print("=" * 60)
    print("  Agentic GenAI Security Accelerator — Quickstart")
    print("=" * 60)
    print()

    # Detect OS
    os_name = platform.system()
    os_label = {"Darwin": "macOS", "Linux": "Linux", "Windows": "Windows"}.get(os_name, os_name)
    print(f"  Detected OS:            {os_label}")
    print(f"  Default mode:           Dry-Run Execution")
    print(f"  Live AWS changes:       Disabled")
    print(f"  Sample findings:        Included")
    print()

    # Validate repo root
    required = ["backend", "dashboard", "scripts", ".env.demo", "sample-data/prowler-output/sample-findings.json"]
    missing = [r for r in required if not Path(r).exists()]
    if missing:
        print("❌ Please run this command from the repository root.")
        print(f"   Missing: {', '.join(missing)}")
        print()
        print("   Expected usage:")
        print("     cd agentic-genai-security-accelerator")
        print("     python3 quickstart.py")
        sys.exit(1)

    # Parse arguments
    setup_only = "--setup-only" in sys.argv
    install_prowler = "--install-prowler" in sys.argv

    if install_prowler:
        _run_prowler_install(os_name)
        return

    # Run setup
    _run_setup(os_name)

    if setup_only:
        print()
        print("Setup complete. Start the dashboard later with:")
        if os_name == "Windows":
            print("  .\\scripts\\run_demo.ps1")
        else:
            print("  ./scripts/run_demo.sh")
        print()
        print("  Dashboard: http://127.0.0.1:8080")
        return

    # Start server
    print()
    _run_server(os_name)


def _run_setup(os_name):
    """Run the setup script for the detected OS."""
    if os_name in ("Darwin", "Linux"):
        script = Path("scripts/setup_demo.sh")
        if not script.exists():
            print(f"❌ {script} not found.")
            sys.exit(1)
        print(f"Running: ./{script}")
        print("-" * 40)
        result = subprocess.run(["bash", str(script)], cwd=os.getcwd())
        if result.returncode != 0:
            print()
            print("⚠️  Setup encountered issues but sample workflow may still work.")
            print("   Try starting the dashboard: ./scripts/run_demo.sh")
    elif os_name == "Windows":
        ps_script = Path("scripts/setup_demo.ps1")
        if ps_script.exists():
            print(f"Running: .\\{ps_script}")
            print("-" * 40)
            subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps_script)], cwd=os.getcwd())
        else:
            print()
            print("  Windows PowerShell scripts are not available yet.")
            print()
            print("  Options:")
            print("    1. Use Git Bash: bash ./scripts/setup_demo.sh")
            print("    2. Use WSL:      ./scripts/setup_demo.sh")
            print("    3. Manual setup:")
            print("       python -m venv .venv")
            print("       .venv\\Scripts\\activate")
            print("       pip install -r requirements.txt")
            print("       copy .env.demo .env")
            print()
    else:
        print(f"⚠️  Unsupported OS: {os_name}. Try running scripts manually.")


def _run_server(os_name):
    """Start the dashboard server."""
    if os_name in ("Darwin", "Linux"):
        script = Path("scripts/run_demo.sh")
        if not script.exists():
            print(f"❌ {script} not found.")
            sys.exit(1)
        print(f"Starting dashboard: ./{script}")
        print("-" * 40)
        print()
        os.execvp("bash", ["bash", str(script)])
    elif os_name == "Windows":
        ps_script = Path("scripts/run_demo.ps1")
        if ps_script.exists():
            print(f"Starting: .\\{ps_script}")
            subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps_script)], cwd=os.getcwd())
        else:
            # Try running with bash (Git Bash on Windows)
            sh_script = Path("scripts/run_demo.sh")
            if sh_script.exists():
                print("Starting with Git Bash: bash ./scripts/run_demo.sh")
                os.execvp("bash", ["bash", str(sh_script)])
            else:
                print()
                print("  To start the dashboard manually:")
                print("    .venv\\Scripts\\python -m backend.main --host 0.0.0.0")
                print()
                print("  Dashboard: http://127.0.0.1:8080")


def _run_prowler_install(os_name):
    """Run the Prowler installation script."""
    print("Installing Prowler for connected AWS scans...")
    print()
    if os_name in ("Darwin", "Linux"):
        script = Path("scripts/install_prowler.sh")
        if script.exists():
            subprocess.run(["bash", str(script)], cwd=os.getcwd())
        else:
            print("❌ scripts/install_prowler.sh not found.")
            print("   Manual install: source .venv/bin/activate && pip install prowler")
    elif os_name == "Windows":
        ps_script = Path("scripts/install_prowler.ps1")
        if ps_script.exists():
            subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps_script)], cwd=os.getcwd())
        else:
            print("  Windows install:")
            print("    .venv\\Scripts\\activate")
            print("    pip install prowler")


if __name__ == "__main__":
    main()
