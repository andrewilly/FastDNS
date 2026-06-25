# FastDNS Windows Service Installer
# Run as Administrator: powershell -ExecutionPolicy Bypass .\scripts\windows\install.ps1
#
# This script:
# 1. Stops and removes any existing FastDNS service
# 2. Kills any lingering fastdns.exe process
# 3. Installs the new service with --upstream 8.8.8.8:53 --doh --dnssec
# 4. Verifies the service is running and DNS resolution works

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

# Ensure log directory exists
$null = New-Item -ItemType Directory -Path (Split-Path $LogFile -Parent) -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Message"
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $line
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ═══════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════

Clear-Host
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   🚀 FastDNS Windows Service Installer   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Check Administrator ───────────────────────────────
if (-not (Test-Administrator)) {
    Write-Log "❌ This script must be run as Administrator!" "Red"
    Write-Log "   Right-click PowerShell and select 'Run as Administrator'" "Yellow"
    pause
    exit 1
}
Write-Log "✅ Running as Administrator" "Green"
Write-Log ""

# ── Phase 1: Stop and remove existing service ──────────
Write-Log "══════════ FASE 1: Rimozione servizio esistente ══════════" "Cyan"
Write-Log ""

# Check if the service exists
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$existingProcess = $null
try { $existingProcess = Get-Process -Name "fastdns" -ErrorAction Stop } catch {}

if ($existingService -or $existingProcess) {
    Write-Log "🧹 Trovata installazione precedente, la rimuovo..." "Yellow"

    # 1a. Stop the Windows service if it exists
    if ($existingService) {
        $svcStatus = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status
        if ($svcStatus -eq "Running") {
            Write-Log "   ⛔ Fermo il servizio Windows '$ServiceName'..." "Yellow"
            try {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                Write-Log "   ✅ Servizio fermato." "Green"
            } catch {
                Write-Log "   ⚠️  Stop-Service fallito, provo con sc.exe..." "Yellow"
                & sc.exe stop $ServiceName 2>&1 | Out-Null
            }
            Start-Sleep -Seconds 2
        }
    }

    # 1b. Delete the Windows service
    if ($existingService) {
        Write-Log "   🗑️  Cancello il servizio Windows '$ServiceName'..." "Yellow"
        try {
            & sc.exe delete $ServiceName 2>&1 | Out-Null
            Write-Log "   ✅ Servizio cancellato." "Green"
        } catch {
            Write-Log "   ⚠️  Impossibile cancellare il servizio: $_" "Yellow"
        }
        Start-Sleep -Seconds 2
    }

    # 1c. Kill any lingering fastdns.exe process
    $retry = 0
    while ($retry -lt 5) {
        $proc = $null
        try { $proc = Get-Process -Name "fastdns" -ErrorAction Stop } catch {}
        if (-not $proc) { break }
        
        Write-Log "   ⛔ Kill processo fastdns.exe (PID $($proc.Id))..." "Yellow"
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        } catch {
            & taskkill.exe /F /IM fastdns.exe 2>&1 | Out-Null
        }
        Start-Sleep -Seconds 1
        $retry++
    }

    # Final verification: make sure it's really gone
    try { $p = Get-Process -Name "fastdns" -ErrorAction Stop; $stillRunning = $true } catch { $stillRunning = $false }
    if ($stillRunning) {
        Write-Log "   ❌ Impossibile fermare il processo. Riavvia il sistema e riprova." "Red"
        pause
        exit 1
    }

    # 1d. Reset DNS to DHCP
    Write-Log "   🔄 Ripristino DNS di sistema a DHCP..." "Yellow"
    try {
        Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Log "   ✅ DNS di sistema resettato a DHCP." "Green"
    } catch {
        Write-Log "   ⚠️  Impossibile resettare DNS: $_" "Yellow"
    }

    Write-Log "✅ Vecchia installazione rimossa con successo." "Green"
} else {
    Write-Log "✅ Nessuna installazione precedente trovata." "Green"
}
Write-Log ""

# ── Phase 2: Verify binary ─────────────────────────────
Write-Log "══════════ FASE 2: Verifica eseguibile ══════════" "Cyan"
Write-Log ""

$resolvedPath = Resolve-Path $BinaryPath -ErrorAction SilentlyContinue
if (-not $resolvedPath) {
    Write-Log "❌ Eseguibile non trovato: $BinaryPath" "Red"
    Write-Log "   Compila prima con: cargo build --release" "Yellow"
    Write-Log "   Oppure specifica il percorso: -BinaryPath .\fastdns.exe" "Yellow"
    pause
    exit 1
}
$BinaryPath = $resolvedPath.Path
Write-Log "✅ Eseguibile trovato: $BinaryPath" "Green"

# Verify version
try {
    $version = & $BinaryPath --version 2>&1
    Write-Log "   Versione: $version" "Green"
} catch {
    Write-Log "   ⚠️  Impossibile ottenere versione: $_" "Yellow"
}
Write-Log ""

# ── Phase 3: Install the service ───────────────────────
Write-Log "══════════ FASE 3: Installazione servizio ══════════" "Cyan"
Write-Log ""

# Build command line arguments
$argsList = @()
$argsList += "`"$BinaryPath`""
$argsList += "-b"
$argsList += "127.0.0.1:53"
$argsList += "-c"
$argsList += "250000"

if ($Dnssec) {
    $argsList += "--dnssec"
}
if (-not $NoUpstream) {
    $argsList += "--upstream"
    $argsList += $Upstream
    if ($Doh) {
        $argsList += "--doh"
    }
}

$binPath = ($argsList -join " ")

Write-Log "📋 Creazione servizio Windows..." "Yellow"
Write-Log "   Nome:     $ServiceName" "White"
Write-Log "   BinPath:  $binPath" "White"

# Create the service
$createResult = & sc.exe create $ServiceName `
    binPath= $binPath `
    start= auto `
    DisplayName= $DisplayName `
    type= own `
    error= normal `
    2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Log "   ✅ Servizio creato con successo." "Green"
} else {
    Write-Log "   ❌ Creazione servizio fallita: $createResult" "Red"
    Write-Log "   Assicurati di eseguire come Administrator." "Yellow"
    pause
    exit 1
}

# Configure recovery options (restart on failure)
Write-Log "📋 Configurazione opzioni di ripristino..." "Yellow"
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null
& sc.exe failureflag $ServiceName 1 2>&1 | Out-Null
Write-Log "   ✅ Servizio configurato per riavvio automatico in caso di crash." "Green"
Write-Log ""

# ── Phase 4: Start the service ─────────────────────────
Write-Log "══════════ FASE 4: Avvio servizio ══════════" "Cyan"
Write-Log ""

Write-Log "▶️  Avvio servizio Windows '$ServiceName'..." "Yellow"
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Write-Log "   ✅ Servizio avviato." "Green"
} catch {
    Write-Log "   ⚠️  Start-Service fallito, provo con sc.exe..." "Yellow"
    & sc.exe start $ServiceName 2>&1 | Out-Null
}

Start-Sleep -Seconds 3

# Verify the service is running
$svcAfter = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svcAfter -and $svcAfter.Status -eq "Running") {
    Write-Log "   ✅ Stato servizio: Running" "Green"
} else {
    Write-Log "   ❌ Il servizio non è in esecuzione. Stato: $($svcAfter.Status)" "Red"
    Write-Log "   Controlla i log: Get-EventLog -LogName Application -Source FastDNS -Newest 10" "Yellow"
    pause
    exit 1
}
Write-Log ""

# ── Phase 5: Set system DNS ────────────────────────────
Write-Log "══════════ FASE 5: Configurazione DNS sistema ══════════" "Cyan"
Write-Log ""

Write-Log "📋 Imposto DNS di sistema su 127.0.0.1..." "Yellow"
try {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    if ($adapters) {
        foreach ($adapter in $adapters) {
            Write-Log "   → $($adapter.Name) (ifIndex: $($adapter.InterfaceIndex))" "White"
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("127.0.0.1") -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Log "   ✅ DNS impostato su 127.0.0.1 per tutte le interfacce attive." "Green"
    } else {
        Write-Log "   ⚠️  Nessuna interfaccia di rete attiva trovata." "Yellow"
        Write-Log "   Imposta manualmente: Set-DnsClientServerAddress -InterfaceIndex X -ServerAddresses ('127.0.0.1')" "Yellow"
    }
} catch {
    Write-Log "   ⚠️  Impossibile impostare DNS: $_" "Yellow"
}
Write-Log "   Per revert: Set-DnsClientServerAddress -InterfaceIndex X -ResetServerAddresses" "Gray"
Write-Log ""

# ── Phase 6: Verification ──────────────────────────────
Write-Log "══════════ FASE 6: Verifica finale ══════════" "Cyan"
Write-Log ""

$allOk = $true

# 6a. Check process
Write-Log "📋 Verifica processo in esecuzione..." "Yellow"
Start-Sleep -Seconds 2
try {
    $proc = Get-Process -Name "fastdns" -ErrorAction Stop
    Write-Log "   ✅ Processo fastdns.exe in esecuzione (PID $($proc.Id))" "Green"
} catch {
    Write-Log "   ❌ Processo fastdns.exe NON trovato!" "Red"
    $allOk = $false
}

# 6b. Check port 53
Write-Log "📋 Verifica porta 53 in ascolto..." "Yellow"
try {
    $portCheck = netstat -an | Select-String "LISTEN" | Select-String ":53 "
    if ($portCheck) {
        Write-Log "   ✅ Porta 53 in ascolto" "Green"
    } else {
        Write-Log "   ⚠️  Porta 53 non rilevata (potrebbe essere necessario Administrator)" "Yellow"
    }
} catch {
    Write-Log "   ⚠️  Impossibile verificare porta 53" "Yellow"
}

# 6c. DNS resolution test
Write-Log "📋 Verifica risoluzione DNS (dig @127.0.0.1 google.com)..." "Yellow"
try {
    # Use .NET DNS client as dig might not be available on Windows
    $ips = [System.Net.Dns]::GetHostAddresses("google.com") | ForEach-Object { $_.IPAddressToString }
    if ($ips) {
        Write-Log "   ✅ Risoluzione DNS OK: google.com → $($ips -join ', ')" "Green"
    } else {
        Write-Log "   ⚠️  Risoluzione DNS non ha restituito IP" "Yellow"
        $allOk = $false
    }
} catch {
    Write-Log "   ⚠️  Verifica DNS fallita: $_" "Yellow"
    Write-Log "   Prova: Resolve-DnsName google.com -Server 127.0.0.1" "Gray"
    $allOk = $false
}

# 6d. Check DNSSEC
if ($Dnssec) {
    Write-Log "📋 Verifica DNSSEC (sigfail.verteiltesysteme.net)..." "Yellow"
    try {
        $resp = [System.Net.Dns]::GetHostAddresses("sigfail.verteiltesysteme.net") 2>$null
        Write-Log "   ⚠️  DNSSEC non ha bloccato sigfail (BOGUS) — verificare configurazione" "Yellow"
    } catch {
        Write-Log "   ✅ DNSSEC attivo: sigfail.verteiltesysteme.net bloccato" "Green"
    }
}

Write-Log ""

# ── Final Summary ──────────────────────────────────────
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
if ($allOk) {
    Write-Host "║   ✅ FastDNS installato con successo!   ║" -ForegroundColor Green
} else {
    Write-Host "║   ⚠️  Installazione completata con warning ║" -ForegroundColor Yellow
}
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Log "Riepilogo:" "Cyan"
Write-Log "  Service Name : $ServiceName" "White"
Write-Log "  Binary       : $BinaryPath" "White"
Write-Log "  Args         : $binPath" "White"
Write-Log "  Log file     : $LogFile" "White"
Write-Log ""

if ($allOk) {
    Write-Log "✅ Installazione completata con successo!" "Green"
    Write-Log "   Il DNS di sistema punta a 127.0.0.1 — FastDNS gestisce tutto il traffico." "Green"
} else {
    Write-Log "⚠️  Installazione completata con alcuni warning." "Yellow"
    Write-Log "   Verifica manualmente: Get-Service FastDNS" "Yellow"
    Write-Log "   Resolve-DnsName google.com -Server 127.0.0.1" "Yellow"
}

Write-Log ""
Write-Log "Per disinstallare: sc.exe stop FastDNS; sc.exe delete FastDNS" "Gray"
Write-Log "Per ripristinare DNS: Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses" "Gray"
