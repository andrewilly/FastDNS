<#
.SYNOPSIS
    FastDNS Windows Service Installer
.DESCRIPTION
    Installs FastDNS as a Windows service with upstream, DoH, DNSSEC.
    Removes any existing installation first, verifies everything works.
    Run as Administrator: powershell -ExecutionPolicy Bypass .\scripts\windows\install.ps1
.PARAMETER BinaryPath
    Path to fastdns.exe (default: .\target\release\fastdns.exe)
.PARAMETER Upstream
    Upstream DNS server (default: 8.8.8.8:53)
.PARAMETER Doh
    Use DNS-over-HTTPS for upstream (default: true)
.PARAMETER Dnssec
    Enable DNSSEC validation (default: true)
.PARAMETER NoUpstream
    Skip upstream, use recursive resolution
#>

param(
    [string]$BinaryPath = ".\target\release\fastdns.exe",
    [string]$Upstream = "8.8.8.8:53",
    [switch]$Doh = $true,
    [switch]$Dnssec = $true,
    [switch]$NoUpstream = $false
)

$ServiceName = "FastDNS"
$DisplayName = "FastDNS Recursive Resolver"
$LogFile = "$env:ProgramData\FastDNS\install.log"

# Ensure log directory
$null = New-Item -ItemType Directory -Path "$env:ProgramData\FastDNS" -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Message"
    try { Write-Host $line -ForegroundColor ([ConsoleColor]::$Color) } catch { Write-Host $line }
    Add-Content -Path $LogFile -Value $line
}

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ═══════════════════════════════════════════
Clear-Host
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   🚀 FastDNS Windows Service Installer   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Admin check ───────────────────────────────
if (-not (Test-Administrator)) {
    Write-Log "❌ Eseguire come Administrator!" "Red"
    Write-Log "   Tasto destro su PowerShell → Esegui come amministratore" "Yellow"
    pause; exit 1
}
Write-Log "✅ Esecuzione come Administrator" "Green"
Write-Log ""

# ── FASE 1: Rimozione vecchia installazione ────
Write-Log "═══════ FASE 1: Rimozione servizio esistente ═══════" "Cyan"
Write-Log ""

$svcExisting = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$procExisting = $null
try { $procExisting = Get-Process -Name "fastdns" -ErrorAction Stop } catch {}

if ($svcExisting -or $procExisting) {
    Write-Log "🧹 Rimozione installazione precedente..." "Yellow"

    # Ferma servizio
    if ($svcExisting -and (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status -eq "Running") {
        Write-Log "   ⛔ Fermo servizio..." "Yellow"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # Cancella servizio
    if ($svcExisting) {
        Write-Log "   🗑️  Cancello servizio..." "Yellow"
        & sc.exe delete $ServiceName 2>$null
        Start-Sleep -Seconds 2
    }

    # Kill processi residui
    for ($i = 0; $i -lt 5; $i++) {
        $p = $null
        try { $p = Get-Process -Name "fastdns" -ErrorAction Stop } catch {}
        if (-not $p) { break }
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }

    # Reset DNS
    Write-Log "   🔄 Ripristino DNS..." "Yellow"
    Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    }
    Write-Log "✅ Rimozione completata." "Green"
} else {
    Write-Log "✅ Nessuna installazione precedente." "Green"
}
Write-Log ""

# ── FASE 2: Verifica eseguibile ──────────────
Write-Log "═══════ FASE 2: Verifica eseguibile ═══════" "Cyan"
Write-Log ""

$fullPath = Resolve-Path $BinaryPath -ErrorAction SilentlyContinue
if (-not $fullPath) {
    Write-Log "❌ File non trovato: $BinaryPath" "Red"
    Write-Log "   Compila: cargo build --release" "Yellow"
    pause; exit 1
}
$BinaryPath = $fullPath.Path
Write-Log "✅ Trovato: $BinaryPath" "Green"

try {
    $ver = & $BinaryPath --version 2>&1
    Write-Log "   Versione: $($ver -join '')" "Green"
} catch { Write-Log "   ⚠️  Versione non disponibile" "Yellow" }
Write-Log ""

# ── FASE 3: Installazione servizio ────────────
Write-Log "═══════ FASE 3: Installazione servizio ═══════" "Cyan"
Write-Log ""

# Costruisci binPath per sc.exe (formato: "eseguibile" --arg1 --arg2)
$argParts = @()
$argParts += "`"$BinaryPath`""
$argParts += "-b 127.0.0.1:53"
$argParts += "-c 250000"
if ($Dnssec) { $argParts += "--dnssec" }
if (-not $NoUpstream) {
    $argParts += "--upstream $Upstream"
    if ($Doh) { $argParts += "--doh" }
}
$binPath = ($argParts -join " ")

Write-Log "📋 Creazione servizio..." "Yellow"
Write-Log "   Nome:    $ServiceName" "White"
Write-Log "   BinPath: $binPath" "White"

# sc.exe create: binPath= e start= hanno UNO spazio dopo il =
& sc.exe create $ServiceName binPath= "$binPath" start= auto DisplayName= "$DisplayName" type= own error= normal 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Log "   ✅ Servizio creato." "Green"
} else {
    Write-Log "   ❌ Creazione fallita (codice: $LASTEXITCODE). Eseguire come Administrator." "Red"
    pause; exit 1
}

# Recovery options (riavvio automatico dopo crash)
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>$null
& sc.exe failureflag $ServiceName 1 2>$null
Write-Log "   ✅ Riavvio automatico configurato." "Green"
Write-Log ""

# ── FASE 4: Avvio servizio ──────────────────
Write-Log "═══════ FASE 4: Avvio servizio ═══════" "Cyan"
Write-Log ""

Write-Log "▶️  Avvio..." "Yellow"
Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

$svcAfter = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svcAfter -and $svcAfter.Status -eq "Running") {
    Write-Log "   ✅ In esecuzione." "Green"
} else {
    Write-Log "   ❌ Stato: $($svcAfter.Status)" "Red"
    Write-Log "   Log: Get-WinEvent -LogName Application | Where-Object { `$_.ProviderName -like '*FastDNS*' } | Format-Table -AutoSize" "Yellow"
    pause; exit 1
}
Write-Log ""

# ── FASE 5: DNS sistema ─────────────────────
Write-Log "═══════ FASE 5: DNS sistema ═══════" "Cyan"
Write-Log ""

Write-Log "📋 Impostazione DNS a 127.0.0.1..." "Yellow"
try {
    Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses ("127.0.0.1") -ErrorAction SilentlyContinue
        Write-Log "   → $($_.Name)" "Gray"
    }
    Write-Log "   ✅ Fatto." "Green"
    Write-Log "   Per revert: Set-DnsClientServerAddress -InterfaceIndex X -ResetServerAddresses" "Gray"
} catch { Write-Log "   ⚠️  Errore: $_" "Yellow" }
Write-Log ""

# ── FASE 6: Verifica finale ─────────────────
Write-Log "═══════ FASE 6: Verifica finale ═══════" "Cyan"
Write-Log ""

$allOk = $true

# Processo
Write-Log "📋 Processo..." "Yellow"
Start-Sleep -Seconds 1
try {
    $p = Get-Process -Name "fastdns" -ErrorAction Stop
    Write-Log "   ✅ PID $($p.Id)" "Green"
} catch { Write-Log "   ❌ Non trovato!" "Red"; $allOk = $false }

# Porta 53
Write-Log "📋 Porta 53..." "Yellow"
try {
    $port = netstat -an 2>$null | Select-String "LISTENING" | Select-String ":53 "
    if ($port) { Write-Log "   ✅ In ascolto" "Green" }
    else { Write-Log "   ⚠️  Non rilevata" "Yellow" }
} catch { Write-Log "   ⚠️  Impossibile verificare" "Yellow" }

# Risoluzione DNS (usa Resolve-DnsName con server esplicito)
Write-Log "📋 Risoluzione DNS (google.com via 127.0.0.1)..." "Yellow"
try {
    $result = Resolve-DnsName "google.com" -Server "127.0.0.1" -Type A -ErrorAction Stop
    $ips = $result | Where-Object { $_.QueryType -eq "A" } | ForEach-Object { $_.IPAddress }
    if ($ips) {
        Write-Log "   ✅ google.com → $($ips -join ', ')" "Green"
    } else { throw "Nessun IP" }
} catch {
    Write-Log "   ⚠️  Fallita: $_" "Yellow"
    Write-Log "   Prova: Resolve-DnsName google.com -Server 127.0.0.1" "Gray"
    $allOk = $false
}

# DNSSEC
if ($Dnssec) {
    Write-Log "📋 DNSSEC..." "Yellow"
    try {
        $null = Resolve-DnsName "sigfail.verteiltesysteme.net" -Server "127.0.0.1" -Type A -ErrorAction Stop
        Write-Log "   ⚠️  sigfail NON bloccato (verificare)" "Yellow"
    } catch {
        Write-Log "   ✅ sigfail bloccato (BOGUS corretto)" "Green"
    }
}

Write-Log ""

# ── Riepilogo finale ─────────────────────────
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
if ($allOk) {
    Write-Host "║   ✅ FastDNS installato con successo!   ║" -ForegroundColor Green
} else {
    Write-Host "║   ⚠️  Installazione completata con warning ║" -ForegroundColor Yellow
}
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Log "Riepilogo:" "Cyan"
Write-Log "  Servizio : $ServiceName" "White"
Write-Log "  Binario  : $BinaryPath" "White"
Write-Log "  Args     : $binPath" "White"
Write-Log "  Log      : $LogFile" "White"
Write-Log ""

if ($allOk) {
    Write-Log "✅ Installazione completata con successo!" "Green"
    Write-Log "   Il DNS di sistema punta a 127.0.0.1." "Green"
} else {
    Write-Log "⚠️  Installazione completata con warning." "Yellow"
}

Write-Log ""
Write-Log "Per disinstallare: sc.exe stop FastDNS; sc.exe delete FastDNS" "Gray"
Write-Log "Per ripristinare DNS: Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses" "Gray"
Write-Log ""

pause
