#!/usr/bin/env python3
"""
Cross-platform quickstart launcher for the Agentic GenAI Security Accelerator.

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

    os_name = platform.system()
    os_label = {
        "Darwin": "macOS",
        "Linux": "Linux",
        "Windows": "Windows",
    }.get(os_name, os_name)

    print(f"  Detected OS:            {os_label}")
    print(f"  Default mode:           Dry-Run Execution")
    print(f"  Live AWS changes:       Disabled")
    print(f"  Sample findings:        Included")
    print()

    required = [
        "backend",
        "dashboard",
        "scripts",
        ".env.demo",
        os.path.join("sample-data", "prowler-output", "sample-findings.json"),
    ]
    missing = [r for r in required if not Path(r).exists()]
    if missing:
        print("ERROR: Please run this command from the repository root.")
        print(f"  Missing: {', '.join(missing)}")
        print()
        print("  Expected usage:")
        print("    cd agentic-genai-security-accelerator")
        print("    python3 quickstart.py")
        sys.exit(1)

    setup_only = "--setup-only" in sys.argv
    install_prowler = "--install-prowler" in sys.argv

    if install_prowler:
        run_prowler_install(os_name)
        return

    run_setup(os_name)

    if setup_only:
        print()
        print("  Setup complete. Start the dashboard later with:")
        if os_name == "Windows":
            print("    .\\scripts\\run_demo.ps1")
        else:
            print("    ./scripts/run_demo.sh")
        print()
        print("  Dashboard: http://127.0.0.1:8080")
        return

    print()
    run_server(os_name)


def run_setup(os_name):
    """Run the setup script for the detected OS."""
    if os_name in ("Darwin", "Linux"):
        script = "scripts/setup_demo.sh"
        if not Path(script).exists():
            print(f"ERROR: {script} not found.")
            sys.exit(1)
        print(f"  Running: ./{script}")
        print("-" * 60)
        subprocess.run(["bash", script])

    elif os_name == "Windows":
        script = "scripts\\setup_demo.ps1"
        if Path(script).exists():
            print(f"  Running: .\\{script}")
            print("-" * 60)
            subprocess.run([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", script
            ])
        else:
            print("  Windows PowerShell scripts are missing.")
            print("  Use Git Bash/WSL or add scripts/setup_demo.ps1")
            print()
            print("  Git Bash alternative:")
            print("    bash ./scripts/setup_demo.sh")
            sys.exit(1)
    else:
        print(f"  Unsupported OS: {os_name}. Run scripts manually.")
        sys.exit(1)


def run_server(os_name):
    """Start the dashboard server."""
    if os_name in ("Darwin", "Linux"):
        script = "scripts/run_demo.sh"
        if not Path(script).exists():
            print(f"ERROR: {script} not found.")
            sys.exit(1)
        print(f"  Starting: ./{script}")
        print("-" * 60)
        print()
        os.execvp("bash", ["bash", script])

    elif os_name == "Windows":
        script = "scripts\\run_demo.ps1"
        if Path(script).exists():
            print(f"  Starting: .\\{script}")
            print("-" * 60)
            subprocess.run([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", script
            ])
        else:
            print("  Windows run script not found.")
            print("  Manual start:")
            print("    .venv\\Scripts\\python -m backend.main --host 0.0.0.0")
            print()
            print("  Dashboard: http://127.0.0.1:8080")


def run_prowler_install(os_name):
    """Run the optional Prowler installation."""
    print("  Installing Prowler for connected AWS scans...")
    print()

    if os_name in ("Darwin", "Linux"):
        script = "scripts/install_prowler.sh"
        if Path(script).exists():
            subprocess.run(["bash", script])
        else:
            print(f"  {script} not found.")
            print("  Manual: source .venv/bin/activate && pip install prowler")

    elif os_name == "Windows":
        script = "scripts\\install_prowler.ps1"
        if Path(script).exists():
            subprocess.run([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", script
            ])
        else:
            print("  Manual install on Windows:")
            print("    .venv\\Scripts\\activate")
            print("    pip install prowler")


if __name__ == "__main__":
    main()
