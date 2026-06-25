# FastDNS Windows Service Installer
# Run as Administrator: powershell -ExecutionPolicy Bypass .\install.ps1

Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   🚀 FastDNS Windows Service Installer   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Check for Administrator privileges
# ---------------------------------------------------------------------------
Write-Host "🔍 Checking for Administrator privileges..." -ForegroundColor Yellow
try {
    $currentPrincipal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    $isAdmin = $currentPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) {
        Write-Host "❌ This script must be run as Administrator!" -ForegroundColor Red
        Write-Host "   Right-click PowerShell and select 'Run as Administrator'"
        pause
        exit 1
    }
    Write-Host "   ✅ Running as Administrator" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to check privileges: $_" -ForegroundColor Red
    pause
    exit 1
}

Write-Host ""

# ---------------------------------------------------------------------------
# Resolve project root from script location
#   Script is at  <project_root>/scripts/windows/install.ps1
#   Project root = <project_root>
# ---------------------------------------------------------------------------
try {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $projectRoot = Join-Path $scriptDir "..\.." | Resolve-Path
    Write-Host "📂 Project root: $projectRoot" -ForegroundColor Cyan
} catch {
    Write-Host "❌ Failed to resolve project root from script location" -ForegroundColor Red
    Write-Host "   Script directory: $scriptDir" -ForegroundColor Red
    pause
    exit 1
}

# ---------------------------------------------------------------------------
# Build the release binary using --manifest-path (no Set-Location needed)
# ---------------------------------------------------------------------------
Write-Host "📦 Building FastDNS release binary..." -ForegroundColor Yellow
$manifestPath = Join-Path $projectRoot "Cargo.toml"
try {
    $buildOutput = & cargo build --release --manifest-path $manifestPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Build failed!" -ForegroundColor Red
        Write-Host "   Build output:" -ForegroundColor Red
        $buildOutput | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
        pause
        exit 1
    }
    Write-Host "   ✅ Build complete" -ForegroundColor Green
} catch {
    Write-Host "❌ Build threw an exception: $_" -ForegroundColor Red
    pause
    exit 1
}

# ---------------------------------------------------------------------------
# Locate the built binary
# ---------------------------------------------------------------------------
$binaryPath = Join-Path $projectRoot "target\release\fastdns.exe"
if (-not (Test-Path $binaryPath)) {
    Write-Host "❌ Release binary not found at: $binaryPath" -ForegroundColor Red
    Write-Host "   Ensure the build completed successfully" -ForegroundColor Red
    pause
    exit 1
}
$binaryPath = (Get-Item $binaryPath).FullName  # normalise to absolute
Write-Host "   📍 Binary: $binaryPath" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Install directory (may contain spaces -> "C:\Program Files\...")
# ---------------------------------------------------------------------------
$installDir = "$env:ProgramFiles\FastDNS"
Write-Host "📋 Installing binary to $installDir ..." -ForegroundColor Yellow
try {
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item $binaryPath "$installDir\fastdns.exe" -Force
    Write-Host "   ✅ Binary installed" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to install binary to $installDir : $_" -ForegroundColor Red
    pause
    exit 1
}

# ---------------------------------------------------------------------------
# Windows Service setup
# ---------------------------------------------------------------------------
Write-Host "📋 Configuring Windows service..." -ForegroundColor Yellow
$serviceName   = "FastDNS"

# The binary path (spaces → quoted).
# The binary runs as a normal daemon when started by the service manager.
$serviceBin    = "$installDir\fastdns.exe"
$dnssecFlag    = "--dnssec"
$serviceCmd    = "`"$serviceBin`" -b 127.0.0.1:53 -c 250000 $dnssecFlag"

# ---------------------------------------------------------------------------
# Stop and remove any existing FastDNS service
# ---------------------------------------------------------------------------
try {
    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "   ⚠️  Service '$serviceName' already exists. Stopping and removing..." -ForegroundColor Yellow
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        Write-Host "   ✅ Removed existing service" -ForegroundColor Green
    }
} catch {
    Write-Host "   ⚠️  Could not remove existing service: $_" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Create the service
#
# IMPORTANT:  sc.exe requires a SPACE after the '=' sign, so each pair is
# two separate arguments:  "binPath="  "value with spaces"
# ---------------------------------------------------------------------------
Write-Host "   Creating service '$serviceName'..." -ForegroundColor Yellow
try {
    $scCreateArgs = @(
        "create", $serviceName,
        "binPath=", $serviceCmd,
        "start=", "auto",
        "DisplayName=", "FastDNS Recursive Resolver",
        "type=", "own",
        "error=", "normal"
    )
    $scResult = & sc.exe $scCreateArgs 2>&1
    $scExit   = $LASTEXITCODE

    if ($scExit -eq 0) {
        Write-Host "   ✅ Service '$serviceName' created" -ForegroundColor Green

        # Set a human-readable description
        & sc.exe description $serviceName "Ultra-fast, independent DNS recursive resolver" | Out-Null

        # Start the service
        Write-Host "🚀 Starting FastDNS service..." -ForegroundColor Yellow
        Start-Service -Name $serviceName
        Start-Sleep -Seconds 2

        # Verify
        $svc = Get-Service -Name $serviceName
        if ($svc.Status -eq "Running") {
            Write-Host "   ✅ Service is running" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Service status: $($svc.Status)" -ForegroundColor Yellow
            Write-Host "   Check Event Viewer for errors:"
            Write-Host "   Get-WinEvent -LogName Application | Where-Object { `$_.ProviderName -like '*FastDNS*' }" -ForegroundColor Cyan
        }
    } else {
        Write-Host "❌ Failed to create service (exit code: $scExit)" -ForegroundColor Red
        Write-Host "   sc.exe output: $scResult" -ForegroundColor Red
        pause
        exit 1
    }
} catch {
    Write-Host "❌ Exception while creating service: $_" -ForegroundColor Red
    pause
    exit 1
}

Write-Host ""
Write-Host "✅ FastDNS installed successfully!" -ForegroundColor Green
Write-Host "   Listening on: 127.0.0.1:53" -ForegroundColor Green
Write-Host "   Binary: $serviceBin" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Service management:" -ForegroundColor Cyan
Write-Host "   Start:   sc start FastDNS"
Write-Host "   Stop:    sc stop FastDNS"
Write-Host "   Status:  sc query FastDNS"
Write-Host ""
Write-Host "📊 Test:    nslookup google.com 127.0.0.1"
Write-Host ""
pause
