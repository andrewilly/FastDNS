<#
.SYNOPSIS
    FastDNS Windows Service Installer
.DESCRIPTION
    Installs FastDNS as a Windows service with upstream, DoH, DNSSEC.
    Removes any existing installation, verifies everything works.
    Run as Administrator.
.PARAMETER BinaryPath
    Path to fastdns.exe (default: .\target\release\fastdns.exe)
#>

param([string]$BinaryPath = ".\target\release\fastdns.exe")

$svc  = "FastDNS"
$log  = "$env:ProgramData\FastDNS\install.log"
$null = New-Item -ItemType Directory -Path "$env:ProgramData\FastDNS" -Force -ErrorAction 0

function log {
    param($m, $c = "White")
    $t = Get-Date -Format "HH:mm:ss"
    $l = "[$t] $m"
    try { Write-Host $l -ForegroundColor $c } catch { Write-Host $l }
    Add-Content -Path $log -Value $l
}

function isAdmin {
    [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Clear-Host
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   🚀 FastDNS Windows Service Installer   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if (-not (isAdmin)) { log "❌ Eseguire come Administrator!" "Red"; pause; exit 1 }
log "✅ Administrator" "Green"
log ""

# ══════════ FASE 1: Pulisci installazione esistente ══════════
log "═══ FASE 1: Pulizia installazione esistente ═══" "Cyan"
log ""

$oldSvc = Get-Service $svc -ErrorAction 0
$oldProc = $null; try { $oldProc = Get-Process fastdns -ErrorAction Stop } catch {}

if ($oldSvc -or $oldProc) {
    log "🧹 Rimozione..." "Yellow"
    if ($oldSvc) {
        if ((Get-Service $svc -ErrorAction 0).Status -eq "Running") {
            log "   ⛔ Fermo servizio..." "Yellow"
            Stop-Service $svc -Force -ErrorAction 0; Start-Sleep 2
        }
        log "   🗑️  Cancello servizio..." "Yellow"
        sc.exe delete $svc 2>$null; Start-Sleep 2
    }
    for ($i = 0; $i -lt 5; $i++) {
        $p = $null; try { $p = Get-Process fastdns -ErrorAction Stop } catch {}
        if (-not $p) { break }
        Stop-Process $p.Id -Force -ErrorAction 0; Start-Sleep 1
    }
    log "   🔄 Reset DNS..." "Yellow"
    Get-NetAdapter -ErrorAction 0 | ForEach-Object {
        Set-DnsClientServerAddress $_.InterfaceIndex -ResetServerAddresses -ErrorAction 0
    }
    log "✅ Fatto." "Green"
} else {
    log "✅ Nessuna installazione precedente." "Green"
}
log ""

# ══════════ FASE 2: Trova binario ══════════
log "═══ FASE 2: Verifica eseguibile ═══" "Cyan"
log ""

$fullPath = Resolve-Path $BinaryPath -ErrorAction 0
if (-not $fullPath) {
    log "❌ File non trovato: $BinaryPath" "Red"
    log "   Compila: cargo build --release" "Yellow"; pause; exit 1
}
$BinaryPath = $fullPath.Path
log "✅ $BinaryPath" "Green"

try {
    $ver = & $BinaryPath --version 2>&1
    log "   Versione: $($ver -join '')" "Green"
} catch { log "   ⚠️  Versione non disponibile" "Yellow" }
log ""

# ══════════ FASE 3: Crea servizio ══════════
log "═══ FASE 3: Creazione servizio ═══" "Cyan"
log ""

# binPath per sc: "eseguibile" --arg1 --arg2 ...
$cmd = "`"$BinaryPath`" -b 127.0.0.1:53 -c 250000 --dnssec --upstream 8.8.8.8:53 --doh"

log "📋 Creazione servizio Windows..." "Yellow"
log "   Nome:    $svc" "White"
log "   BinPath: $cmd" "White"

sc.exe create $svc binPath= $cmd start= auto DisplayName= "FastDNS Recursive Resolver" type= own error= normal 2>$null
if ($LASTEXITCODE -ne 0) {
    log "❌ Creazione fallita (codice: $LASTEXITCODE)." "Red"
    log "   Eseguire come Administrator." "Yellow"; pause; exit 1
}
log "   ✅ Servizio creato." "Green"

sc.exe failure $svc reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>$null
sc.exe failureflag $svc 1 2>$null
log "   ✅ Riavvio automatico configurato." "Green"
log ""

# ══════════ FASE 4: Avvia ══════════
log "═══ FASE 4: Avvio ═══" "Cyan"
log ""
log "▶️  Avvio..." "Yellow"
Start-Service $svc -ErrorAction 0; Start-Sleep 3

$stato = (Get-Service $svc -ErrorAction 0).Status
if ($stato -eq "Running") {
    log "   ✅ In esecuzione." "Green"
} else {
    log "❌ Stato: $stato" "Red"
    log "   Get-WinEvent -LogName Application | Where-Object { `$_.ProviderName -like '*FastDNS*' }" "Yellow"
    pause; exit 1
}
log ""

# ══════════ FASE 5: DNS sistema ══════════
log "═══ FASE 5: DNS sistema ═══" "Cyan"
log ""
log "📋 Imposto DNS a 127.0.0.1..." "Yellow"

$ok = $true
try {
    Get-NetAdapter -ErrorAction 0 | Where-Object Status -eq Up | ForEach-Object {
        Set-DnsClientServerAddress $_.InterfaceIndex -ServerAddresses 127.0.0.1 -ErrorAction 0
        log "   → $($_.Name)" "Gray"
    }
    log "   ✅ DNS impostato." "Green"
    log "   Per revert: Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses" "Gray"
} catch { log "   ⚠️  $($_.Exception.Message)" "Yellow" }
log ""

# ══════════ FASE 6: Verifica ══════════
log "═══ FASE 6: Verifica ═══" "Cyan"
log ""

# 6a. Processo
Start-Sleep 1
try {
    $p = Get-Process fastdns -ErrorAction Stop
    log "   ✅ Processo PID $($p.Id)" "Green"
} catch { log "   ❌ Processo non trovato!" "Red"; $ok = $false }

# 6b. Porta 53
try {
    $r = netstat -an 2>$null | Select-String LISTENING | Select-String ":53 "
    if ($r) { log "   ✅ Porta 53 in ascolto" "Green" }
    else { log "   ⚠️  Porta 53 non rilevata" "Yellow" }
} catch { log "   ⚠️  Verifica porta fallita" "Yellow" }

# 6c. Risoluzione DNS
try {
    $r = Resolve-DnsName google.com -Server 127.0.0.1 -Type A -ErrorAction Stop
    $ips = $r.IPAddress -join ", "
    log "   ✅ google.com → $ips" "Green"
} catch {
    log "   ⚠️  Fallita: $($_.Exception.Message)" "Yellow"
    log "   Prova: Resolve-DnsName google.com -Server 127.0.0.1" "Gray"
    $ok = $false
}

# 6d. DNSSEC
try {
    $null = Resolve-DnsName sigfail.verteiltesysteme.net -Server 127.0.0.1 -Type A -ErrorAction Stop
    log "   ⚠️  sigfail NON bloccato (verificare DNSSEC)" "Yellow"
} catch {
    log "   ✅ DNSSEC: sigfail bloccato (BOGUS)" "Green"
}

log ""

# ══════════ RIEPILOGO ══════════
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
if ($ok) {
    Write-Host "║   ✅ FastDNS installato con successo!   ║" -ForegroundColor Green
} else {
    Write-Host "║   ⚠️  Installazione completata con warning ║" -ForegroundColor Yellow
}
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
log "Riepilogo:" "Cyan"
log "  Servizio : $svc" "White"
log "  Binario  : $BinaryPath" "White"
log "  Args     : $cmd" "White"
log "  Log      : $log" "White"
log ""
log "Per disinstallare:" "Gray"
log "  sc.exe stop $svc; sc.exe delete $svc" "Gray"
log "  Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses" "Gray"
log ""

pause
