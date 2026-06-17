# Agentic GenAI Security Accelerator — Install Prowler (Windows)
# Prowler is optional. Only needed for connected AWS security scans.

$ErrorActionPreference = "Continue"

Write-Host "=== Prowler Installation ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Prowler is an open-source AWS security assessment tool."
Write-Host "  Installation may take several minutes due to its dependencies."
Write-Host ""
Write-Host "  Prowler is NOT required for the sample workflow."
Write-Host "  Install only if you want to run a connected AWS scan."
Write-Host ""

# Check if already installed
$prowlerPath = & .venv\Scripts\python -c "import shutil; print(shutil.which('prowler') or '')" 2>$null
if ($prowlerPath) {
    Write-Host "  Prowler is already installed: $prowlerPath" -ForegroundColor Green
    exit 0
}

# Check venv
if (-not (Test-Path ".venv\Scripts\pip.exe")) {
    Write-Host "ERROR: .venv not found. Run .\scripts\setup_demo.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "  Installing Prowler into .venv (this may take 5-10 minutes)..."
Write-Host ""

& .venv\Scripts\pip install prowler

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "  Prowler installed successfully." -ForegroundColor Green
    Write-Host "  You can now run connected AWS scans from the dashboard."
} else {
    Write-Host ""
    Write-Host "  Prowler installation failed." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  The sample workflow is still available without Prowler."
    Write-Host "  Troubleshooting:"
    Write-Host "    - Python 3.10+ is recommended for Prowler"
    Write-Host "    - Try: pip install prowler --verbose"
}
