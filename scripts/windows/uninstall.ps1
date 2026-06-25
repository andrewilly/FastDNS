# FastDNS Windows Service Uninstaller
# Run as Administrator: powershell -ExecutionPolicy Bypass .\uninstall.ps1

Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  🚀 FastDNS Windows Service Uninstaller   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check for Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "❌ This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "   Right-click PowerShell and select 'Run as Administrator'"
    pause
    exit 1
}

$serviceName = "FastDNS"
$installDir = "$env:ProgramFiles\FastDNS"

# Stop and delete the service
Write-Host "🛑 Stopping FastDNS service..." -ForegroundColor Yellow
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "   ✅ Service stopped" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  Service not found" -ForegroundColor Yellow
}

Write-Host "📋 Removing service..." -ForegroundColor Yellow
sc.exe delete $serviceName | Out-Null
if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1060) {
    Write-Host "   ✅ Service removed" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Service removal returned code $LASTEXITCODE" -ForegroundColor Yellow
}

# Remove files
if (Test-Path $installDir) {
    Write-Host "📋 Removing binary files..." -ForegroundColor Yellow
    Remove-Item -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "   ✅ Files removed from $installDir" -ForegroundColor Green
}

Write-Host ""
Write-Host "✅ FastDNS has been uninstalled." -ForegroundColor Green
pause
