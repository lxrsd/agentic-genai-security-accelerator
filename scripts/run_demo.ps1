# Agentic GenAI Security Accelerator - Windows Dashboard Launcher

$ErrorActionPreference = "Continue"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"

# Check venv
if (-not (Test-Path $PythonExe)) {
    Write-Host "ERROR: .venv not found. Run .\scripts\setup_demo.ps1 first." -ForegroundColor Red
    exit 1
}

# Create .env from .env.demo if missing
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.demo") {
        Copy-Item ".env.demo" ".env"
        Write-Host "  Created .env from .env.demo (safe dry-run mode)" -ForegroundColor Green
        Write-Host ""
    }
}

# Read mode from .env for display
$dryRun = "true"
$execEnabled = "false"
$investigationEnabled = "false"
$planningEnabled = "false"

if (Test-Path ".env") {
    $envLines = Get-Content ".env"
    foreach ($line in $envLines) {
        if ($line -match "^DRY_RUN_REMEDIATION=(.+)") { $dryRun = $Matches[1].Trim() }
        if ($line -match "^REMEDIATION_EXECUTION_ENABLED=(.+)") { $execEnabled = $Matches[1].Trim() }
        if ($line -match "^INVESTIGATION_TOOLS_ENABLED=(.+)") { $investigationEnabled = $Matches[1].Trim() }
        if ($line -match "^REMEDIATION_PLANNING_ENABLED=(.+)") { $planningEnabled = $Matches[1].Trim() }
    }
}

# Startup summary
Write-Host "=== Agentic GenAI Security Accelerator ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Sample findings: sample-data\prowler-output\sample-findings.json"

if (($execEnabled -eq "true") -and ($dryRun -eq "true")) {
    Write-Host "  Mode:            Dry-Run Execution" -ForegroundColor Blue
    Write-Host "  Live AWS changes: Disabled" -ForegroundColor Green
} elseif (($execEnabled -eq "true") -and ($dryRun -eq "false")) {
    Write-Host "  Mode:            Live Low-Risk Execution" -ForegroundColor Red
    Write-Host "  Live AWS changes: ENABLED (low-risk only)" -ForegroundColor Red
} else {
    Write-Host "  Mode:            Planning Only"
    Write-Host "  Live AWS changes: Disabled" -ForegroundColor Green
}

Write-Host "  Investigation:   $investigationEnabled"
Write-Host "  Planning:        $planningEnabled"
Write-Host "  Execution:       $execEnabled"
Write-Host "  Dry-run:         $dryRun"
Write-Host ""
Write-Host "  Dashboard: http://127.0.0.1:8080" -ForegroundColor White
Write-Host ""

# Start server
& $PythonExe -m backend.main --host 0.0.0.0
