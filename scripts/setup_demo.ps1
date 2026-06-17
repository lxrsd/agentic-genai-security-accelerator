# Agentic GenAI Security Accelerator - Windows Setup
# Installs core dependencies. Prowler is NOT installed by default.

$ErrorActionPreference = "Continue"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

Write-Host "=== Agentic GenAI Security Accelerator - Setup ===" -ForegroundColor Cyan
Write-Host ""

# Find Python
$PythonCmd = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonCmd = "py"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $PythonCmd = "python3"
}

if (-not $PythonCmd) {
    Write-Host "ERROR: Python is required. Install from https://python.org" -ForegroundColor Red
    exit 1
}

$PyVersion = & $PythonCmd --version 2>&1
Write-Host "  Python: $PyVersion" -ForegroundColor Green

# Create venv if missing
if (-not (Test-Path ".venv")) {
    Write-Host "  Creating virtual environment..."
    & $PythonCmd -m venv .venv
}
Write-Host "  Virtual environment ready" -ForegroundColor Green

# Define paths
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$PipExe = Join-Path $RepoRoot ".venv\Scripts\pip.exe"

if (-not (Test-Path $PythonExe)) {
    Write-Host "ERROR: .venv\Scripts\python.exe not found after venv creation." -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host ""
Write-Host "  Installing Python dependencies..."
& $PipExe install --upgrade pip setuptools wheel -q 2>$null
& $PipExe install -r requirements.txt -q
Write-Host "  Core dependencies installed" -ForegroundColor Green

# Prowler check (native PowerShell - no inline Python)
Write-Host ""
Write-Host "--- Prowler Status ---"
$prowlerCmd = Get-Command prowler -ErrorAction SilentlyContinue
if ($prowlerCmd) {
    Write-Host "  Prowler CLI: Found" -ForegroundColor Green
} else {
    Write-Host "  Prowler CLI: Not installed" -ForegroundColor Yellow
    Write-Host "  Prowler is optional for the sample workflow."
    Write-Host "  Sample findings are already included."
    Write-Host "  Connected AWS scans require Prowler."
    Write-Host "  To install later: .\scripts\install_prowler.ps1"
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
$samplePath = Join-Path $RepoRoot "sample-data\prowler-output\sample-findings.json"
if (Test-Path $samplePath) {
    Write-Host "  Sample findings available" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Sample findings not found." -ForegroundColor Yellow
}

# AWS CLI check (informational)
Write-Host ""
$awsCmd = Get-Command aws -ErrorAction SilentlyContinue
if ($awsCmd) {
    Write-Host "  AWS CLI: Found" -ForegroundColor Green
} else {
    Write-Host "  AWS CLI: Not found (optional for sample workflow)" -ForegroundColor Yellow
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
