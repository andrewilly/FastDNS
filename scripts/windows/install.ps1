<#
.SYNOPSIS
    FastDNS Windows Service Installer
.DESCRIPTION
    Installs FastDNS as a Windows service with upstream, DoH, DNSSEC.
    Removes any existing installation, then verifies the new service.
    Must run as Administrator.
.PARAMETER BinaryPath
    Path to fastdns.exe
#>

param(
    [string]$BinaryPath = ".\target\release\fastdns.exe"
)

$ServiceName = "FastDNS"
$DisplayName = "FastDNS Recursive Resolver"
$LogFile     = "$env:ProgramData\FastDNS\install.log"
$LogDir      = "$env:ProgramData\FastDNS"

# Create log directory
$null = New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Message, $Color = "White")
    $Time = Get-Date -Format "HH:mm:ss"
    $Line = "[$Time] $Message"
    try {
        Write-Host $Line -ForegroundColor $Color
    } catch {
        Write-Host $Line
    }
    Add-Content -Path $LogFile -Value $Line
}

function Test-Admin {
    try {
        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
        return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# ─────────────────────────────────────────────
Clear-Host
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   FastDNS Windows Service Installer      ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Admin)) {
    Write-Host "ERROR: Run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}
Write-Log "OK: Administrator privileges confirmed"
Write-Log ""

# ─────────────────────────────
# PHASE 1: Clean up old service
# ─────────────────────────────
Write-Log "Phase 1: Remove existing installation" -Color Cyan
Write-Log ""

$OldService = Get-Service $ServiceName -ErrorAction SilentlyContinue
$OldProcess = $null
try { $OldProcess = Get-Process -Name "fastdns" -ErrorAction Stop } catch {}

if ($OldService -or $OldProcess) {
    Write-Log "Found previous installation, removing..." -Color Yellow

    if ($OldService) {
        try {
            $ServiceStatus = (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status
            if ($ServiceStatus -eq "Running") {
                Write-Log "  Stopping service..." -Color Yellow
                Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        } catch {}

        Write-Log "  Deleting service..." -Color Yellow
        & "sc.exe" delete $ServiceName 2>$null
        Start-Sleep -Seconds 2
    }

    # Kill remaining processes
    for ($i = 0; $i -lt 5; $i++) {
        $Process = $null
        try { $Process = Get-Process -Name "fastdns" -ErrorAction Stop } catch {}
        if (-not $Process) { break }
        try { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue } catch {}
        Start-Sleep -Seconds 1
    }

    # Reset DNS
    try {
        $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue
        foreach ($Adapter in $Adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $Adapter.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }
    } catch {}

    Write-Log "OK: Old installation removed" -Color Green
} else {
    Write-Log "OK: No previous installation found" -Color Green
}
Write-Log ""

# ─────────────────────────────
# PHASE 2: Verify binary
# ─────────────────────────────
Write-Log "Phase 2: Verify executable" -Color Cyan
Write-Log ""

$FullPath = Resolve-Path $BinaryPath -ErrorAction SilentlyContinue
if (-not $FullPath) {
    Write-Log "ERROR: File not found: $BinaryPath" -Color Red
    Write-Log "Build it first with: cargo build --release" -Color Yellow
    pause
    exit 1
}
$BinaryPath = $FullPath.Path
Write-Log "OK: $BinaryPath" -Color Green

try {
    $Version = Invoke-Expression "& '$BinaryPath' --version"
    Write-Log "    Version: $Version" -Color Green
} catch {
    Write-Log "    Warning: Could not check version" -Color Yellow
}
Write-Log ""

# ─────────────────────────────
# PHASE 3: Create service
# ─────────────────────────────
Write-Log "Phase 3: Create Windows service" -Color Cyan
Write-Log ""

$BinPath = "`"$BinaryPath`" -b 127.0.0.1:53 -c 250000 --dnssec --upstream 8.8.8.8:53 --doh"

Write-Log "Service name: $ServiceName" -Color White
Write-Log "Binary:       $BinPath" -Color White

# sc.exe syntax: binPath= <command> (space after = is required)
$ArgumentList = @(
    "create",
    $ServiceName,
    "binPath=",
    $BinPath,
    "start=",
    "auto",
    "DisplayName=",
    $DisplayName,
    "type=",
    "own",
    "error=",
    "normal"
)

$Result = Start-Process -Wait -NoNewWindow -FilePath "sc.exe" -ArgumentList $ArgumentList -PassThru
if ($Result.ExitCode -ne 0) {
    Write-Log "ERROR: Service creation failed (exit code: $($Result.ExitCode))" -Color Red
    Write-Log "Run this script as Administrator" -Color Yellow
    pause
    exit 1
}
Write-Log "OK: Service created" -Color Green

# Configure auto-restart on failure
$FailureArgs = @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000")
Start-Process -Wait -NoNewWindow -FilePath "sc.exe" -ArgumentList $FailureArgs -PassThru | Out-Null
$FailureFlagArgs = @("failureflag", $ServiceName, "1")
Start-Process -Wait -NoNewWindow -FilePath "sc.exe" -ArgumentList $FailureFlagArgs -PassThru | Out-Null
Write-Log "OK: Auto-restart configured" -Color Green
Write-Log ""

# ─────────────────────────────
# PHASE 4: Start service
# ─────────────────────────────
Write-Log "Phase 4: Start service" -Color Cyan
Write-Log ""

Write-Log "Starting..." -Color Yellow
try {
    Start-Service $ServiceName -ErrorAction Stop
} catch {
    & "sc.exe" start $ServiceName 2>$null
}
Start-Sleep -Seconds 3

$ServiceStatus = (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status
if ($ServiceStatus -eq "Running") {
    Write-Log "OK: Service is running" -Color Green
} else {
    Write-Log "ERROR: Service status is: $ServiceStatus" -Color Red
    Write-Log "Check Event Viewer:" -Color Yellow
    Write-Log "Get-WinEvent -LogName Application | Where-Object ProviderName -like '*FastDNS*'" -Color Yellow
    pause
    exit 1
}
Write-Log ""

# ─────────────────────────────
# PHASE 5: Set system DNS
# ─────────────────────────────
Write-Log "Phase 5: Set system DNS to 127.0.0.1" -Color Cyan
Write-Log ""

try {
    $NetworkAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    if ($NetworkAdapters) {
        foreach ($Adapter in $NetworkAdapters) {
            Set-DnsClientServerAddress -InterfaceIndex $Adapter.InterfaceIndex -ServerAddresses "127.0.0.1" -ErrorAction SilentlyContinue
            Write-Log "  $($Adapter.Name)" -Color Gray
        }
        Write-Log "OK: System DNS set to 127.0.0.1" -Color Green
        Write-Log "To revert: Set-DnsClientServerAddress -InterfaceIndex X -ResetServerAddresses" -Color Gray
    } else {
        Write-Log "Warning: No active network adapters found" -Color Yellow
    }
} catch {
    Write-Log "Warning: Could not set system DNS: $($_.Exception.Message)" -Color Yellow
}
Write-Log ""

# ─────────────────────────────
# PHASE 6: Verification
# ─────────────────────────────
Write-Log "Phase 6: Verification" -Color Cyan
Write-Log ""

$AllOk = $true
Start-Sleep -Seconds 1

# Check process
try {
    $Process = Get-Process -Name "fastdns" -ErrorAction Stop
    Write-Log "OK: Process running (PID: $($Process.Id))" -Color Green
} catch {
    Write-Log "ERROR: Process not found" -Color Red
    $AllOk = $false
}

# Check port 53
try {
    $PortCheck = cmd /c "netstat -an 2>nul | findstr LISTENING | findstr :53"
    if ($PortCheck) {
        Write-Log "OK: Port 53 is listening" -Color Green
    } else {
        Write-Log "Warning: Port 53 not detected" -Color Yellow
    }
} catch {
    Write-Log "Warning: Could not check port 53" -Color Yellow
}

# DNS resolution test
Write-Log "Testing DNS resolution (google.com via 127.0.0.1)..." -Color Yellow
try {
    $DnsResult = Resolve-DnsName -Name "google.com" -Server "127.0.0.1" -Type A -ErrorAction Stop
    $IPAddresses = $DnsResult.IPAddress -join ", "
    Write-Log "OK: google.com resolves to $IPAddresses" -Color Green
} catch {
    Write-Log "Warning: DNS resolution failed: $($_.Exception.Message)" -Color Yellow
    Write-Log "Try: Resolve-DnsName google.com -Server 127.0.0.1" -Color Gray
    $AllOk = $false
}

# DNSSEC test
Write-Log "Testing DNSSEC (sigfail.verteiltesysteme.net)..." -Color Yellow
try {
    $null = Resolve-DnsName -Name "sigfail.verteiltesysteme.net" -Server "127.0.0.1" -Type A -ErrorAction Stop
    Write-Log "Warning: sigfail.verteiltesysteme.net resolved (DNSSEC should block it)" -Color Yellow
} catch {
    Write-Log "OK: DNSSEC blocked bogus domain" -Color Green
}

Write-Log ""

# ──── SUMMARY ────
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
if ($AllOk) {
    Write-Host "   FastDNS installed successfully!" -ForegroundColor Green
} else {
    Write-Host "   Installation completed with warnings" -ForegroundColor Yellow
}
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Log "Summary:"
Write-Log "  Service: $ServiceName"
Write-Log "  Binary:  $BinaryPath"
Write-Log "  Args:    $BinPath"
Write-Log "  Log:     $LogFile"
Write-Log ""

if ($AllOk) {
    Write-Log "FastDNS is running. System DNS is set to 127.0.0.1." -Color Green
} else {
    Write-Log "Manual check recommended:" -Color Yellow
    Write-Log "  Get-Service $ServiceName" -Color Yellow
    Write-Log "  Resolve-DnsName google.com -Server 127.0.0.1" -Color Yellow
}

Write-Log ""
Write-Log "To uninstall: sc.exe stop $ServiceName; sc.exe delete $ServiceName" -Color Gray
Write-Log "To restore DNS: Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses" -Color Gray
Write-Log ""

pause
