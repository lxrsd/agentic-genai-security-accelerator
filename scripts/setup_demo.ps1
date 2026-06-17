# Agentic GenAI Security Accelerator — Windows Setup
# Installs core dependencies. Prowler is NOT installed by default.
# Use --with-prowler or .\scripts\install_prowler.ps1 for connected AWS scans.

$ErrorActionPreference = "Continue"

Write-Host "=== Agentic GenAI Security Accelerator — Setup ===" -ForegroundColor Cyan
Write-Host ""

# Check Python
$python = $null
if (Get-Command py -ErrorAction SilentlyContinue) { $python = "py" }
elseif (Get-Command python -ErrorAction SilentlyContinue) { $python = "python" }
elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $python = "python3" }

if (-not $python) {
    Write-Host "ERROR: Python is required. Install Python from https://python.org" -ForegroundColor Red
    exit 1
}

$pyVersion = & $python --version 2>&1
Write-Host "  Python: $pyVersion" -ForegroundColor Green

# Check Python version
$versionNum = & $python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$major = & $python -c "import sys; print(sys.version_info.major)"
$minor = & $python -c "import sys; print(sys.version_info.minor)"

if ([int]$major -eq 3 -and [int]$minor -lt 10) {
    Write-Host ""
    Write-Host "  WARNING: Python 3.10+ is recommended. Some deps may fail on $versionNum." -ForegroundColor Yellow
    Write-Host ""
}

# Create venv
if (-not (Test-Path ".venv")) {
    Write-Host "  Creating virtual environment..."
    & $python -m venv .venv
}
Write-Host "  Virtual environment ready" -ForegroundColor Green

# Activate venv
$activateScript = ".venv\Scripts\Activate.ps1"
if (Test-Path $activateScript) {
    & $activateScript
}

# Install dependencies
Write-Host ""
Write-Host "  Installing Python dependencies..."
& .venv\Scripts\pip install --upgrade pip -q 2>$null
& .venv\Scripts\pip install -r requirements.txt -q
Write-Host "  Core dependencies installed" -ForegroundColor Green

# Prowler status
Write-Host ""
Write-Host "--- Prowler Status ---"
$prowlerExists = & .venv\Scripts\python -c "import shutil; print('yes' if shutil.which('prowler') else 'no')" 2>$null
if ($prowlerExists -eq "yes") {
    Write-Host "  Prowler found" -ForegroundColor Green
} else {
    Write-Host "  Prowler is NOT required for the sample workflow." -ForegroundColor Yellow
    Write-Host "  Sample findings are already included."
    Write-Host "  Connected AWS scans require Prowler."
    Write-Host "  Install later: .\scripts\install_prowler.ps1"
    Write-Host ""
}

# Copy config files
Write-Host ""
if (-not (Test-Path ".env")) {
    Copy-Item ".env.demo" ".env"
    Write-Host "  .env created from .env.demo (safe dry-run mode)" -ForegroundColor Green
} else {
    Write-Host "  .env already exists (not overwriting)" -ForegroundColor Green
}

if (-not (Test-Path "mcp_config.json")) {
    if (Test-Path "mcp_config.example.json") {
        Copy-Item "mcp_config.example.json" "mcp_config.json"
        Write-Host "  mcp_config.json created" -ForegroundColor Green
    }
} else {
    Write-Host "  mcp_config.json already exists" -ForegroundColor Green
}

# Confirm sample findings
Write-Host ""
if (Test-Path "sample-data\prowler-output\sample-findings.json") {
    Write-Host "  Sample findings available" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Sample findings not found." -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Sample findings: Included"
Write-Host "  Default mode:    Dry-Run Execution (no AWS changes)"
Write-Host "  AWS credentials: Optional for sample workflow"
Write-Host ""
Write-Host "  Start the dashboard:"
Write-Host "    .\scripts\run_demo.ps1" -ForegroundColor White
Write-Host ""
Write-Host "  Dashboard: http://127.0.0.1:8080"
Write-Host ""
