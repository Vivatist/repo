<#
.SYNOPSIS
    Бенчмарк GRO/GSO — сравнение производительности с GRO и без.

.DESCRIPTION
    Автоматически:
    1. Деплоит vpnbench на сервер
    2. Отключает GRO → перезапускает → прогоняет быстрый бенч
    3. Включает GRO → перезапускает → прогоняет быстрый бенч
    4. Сравнивает результаты

    Конфигурация: deploy-config.json (рядом со скриптом).

.PARAMETER duration
    Длительность каждого теста (по умолчанию: 15s)

.EXAMPLE
    .\bench-gro.ps1
    .\bench-gro.ps1 -duration 30s
#>

param(
    [string]$duration = "15s"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir

# ═══════════════════════════════════════════════
#  1. Загрузка конфигурации
# ═══════════════════════════════════════════════

$configPath = Join-Path $scriptDir "deploy-config.json"
if (-not (Test-Path $configPath)) {
    Write-Host "[ОШИБКА] Файл конфигурации не найден: $configPath" -ForegroundColor Red
    exit 1
}

$cfg = Get-Content $configPath -Raw -Encoding UTF8 | ConvertFrom-Json

$sshHost      = $cfg.ssh_host
$sshPort      = if ($cfg.ssh_port)           { [int]$cfg.ssh_port }           else { 22 }
$sshUser      = $cfg.ssh_user
$sshPass      = $cfg.ssh_password
$vpnPort      = if ($cfg.vpn_port)           { [int]$cfg.vpn_port }           else { 443 }
$testEmail    = if ($cfg.test_user_email)     { $cfg.test_user_email }         else { "test@novavpn.app" }
$testPassword = if ($cfg.test_user_password)  { $cfg.test_user_password }      else { "NovaVPN2026!" }

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║    NovaVPN — Бенчмарк GRO/GSO (on vs off)     ║" -ForegroundColor Magenta
Write-Host "  ╠═══════════════════════════════════════════════╣" -ForegroundColor Magenta
Write-Host ("  ║  Сервер:    {0}@{1}" -f $sshUser, $sshHost).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
Write-Host ("  ║  Время:     {0} на каждый тест" -f $duration).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ═══════════════════════════════════════════════
#  2. Posh-SSH
# ═══════════════════════════════════════════════

if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Host "[SSH] Установка Posh-SSH..." -ForegroundColor Yellow
    Install-Module -Name Posh-SSH -Force -Scope CurrentUser -AllowClobber
}
Import-Module Posh-SSH -ErrorAction Stop

# ═══════════════════════════════════════════════
#  3. Сборка vpnbench
# ═══════════════════════════════════════════════

Write-Host "[BUILD] Сборка vpnbench (linux/amd64)..." -ForegroundColor Cyan

$binaryPath = Join-Path $scriptDir "vpnbench"

Push-Location $projectDir
try {
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    $buildOutput = & go build -ldflags="-s -w" -o $binaryPath ./cmd/vpnbench/ 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ОШИБКА] Сборка не удалась:" -ForegroundColor Red
        $buildOutput | ForEach-Object { Write-Host "  $_" }
        exit 1
    }
} finally {
    Pop-Location
    Remove-Item Env:GOOS        -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH      -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
}

$fileSize = [math]::Round((Get-Item $binaryPath).Length / 1MB, 1)
Write-Host "[BUILD] Готово ($fileSize МБ)" -ForegroundColor Green

# ═══════════════════════════════════════════════
#  4. Подключение и деплой
# ═══════════════════════════════════════════════

Write-Host "[SSH] Подключение к $sshHost..." -ForegroundColor Cyan

$secPass = ConvertTo-SecureString $sshPass -AsPlainText -Force
$cred    = New-Object System.Management.Automation.PSCredential($sshUser, $secPass)
$session = New-SSHSession -ComputerName $sshHost -Port $sshPort -Credential $cred -AcceptKey -Force

if (-not $session -or -not $session.Connected) {
    Write-Host "[ОШИБКА] Не удалось подключиться" -ForegroundColor Red
    exit 1
}
Write-Host "[SSH] Подключено" -ForegroundColor Green

# Загружаем бенчмарк
Write-Host "[SCP] Загрузка vpnbench..." -ForegroundColor Cyan
Set-SCPItem -ComputerName $sshHost -Port $sshPort -Credential $cred -Path $binaryPath -Destination "/tmp/" -AcceptKey -Force
$null = Invoke-SSHCommand -SSHSession $session -Command "chmod +x /tmp/vpnbench"
Write-Host "[SCP] Готово" -ForegroundColor Green

# PSK
$r = Invoke-SSHCommand -SSHSession $session -Command "grep pre_shared_key /etc/novavpn/server.yaml | awk -F'""' '{print `$2}'"
$psk = ($r.Output | Out-String).Trim()
if (-not $psk -or $psk.Length -ne 64) {
    Write-Host "[ОШИБКА] PSK не найден" -ForegroundColor Red
    Remove-SSHSession -SSHSession $session | Out-Null
    exit 1
}
Write-Host "[CONFIG] PSK получен" -ForegroundColor Green

# Версия ядра
$r = Invoke-SSHCommand -SSHSession $session -Command "uname -r"
$kernelVersion = ($r.Output | Out-String).Trim()
Write-Host "[CONFIG] Ядро: $kernelVersion" -ForegroundColor Cyan

# ═══════════════════════════════════════════════
#  Функция запуска одного теста
# ═══════════════════════════════════════════════

$durationSec = 30
if ($duration -match '^(\d+)s$') { $durationSec = [int]$Matches[1] }
$timeoutSec = $durationSec + 120

function Run-BenchTest {
    param(
        [string]$Label,
        [string]$Mode,
        [int]$Clients,
        [string]$JsonFile
    )

    $benchCmd = "/tmp/vpnbench " +
        "-server 127.0.0.1:$vpnPort " +
        "-psk '$psk' " +
        "-email '$testEmail' " +
        "-password '$testPassword' " +
        "-clients $Clients " +
        "-duration $duration " +
        "-interval 100ms " +
        "-mode $Mode " +
        "-json $JsonFile " +
        "2>&1"

    Write-Host "    [$Label] Запуск: $Mode, $Clients клиент(ов)..." -ForegroundColor DarkGray

    $r = Invoke-SSHCommand -SSHSession $session -Command $benchCmd -TimeOut $timeoutSec

    # Читаем JSON
    $jr = Invoke-SSHCommand -SSHSession $session -Command "cat $JsonFile 2>/dev/null"
    if ($jr.Output) {
        try {
            return ($jr.Output | Out-String | ConvertFrom-Json)
        } catch {
            Write-Host "    [WARN] JSON parse error" -ForegroundColor Yellow
            return $null
        }
    }
    return $null
}

function Set-GROConfig {
    param([string]$Value)

    # Проверяем, есть ли уже enable_gro_gso в конфиге
    $r = Invoke-SSHCommand -SSHSession $session -Command "grep -q enable_gro_gso /etc/novavpn/server.yaml 2>/dev/null && echo YES || echo NO"
    $has = (($r.Output | Out-String).Trim() -split "`n")[-1].Trim()

    if ($has -eq "YES") {
        # Заменяем существующее значение
        $null = Invoke-SSHCommand -SSHSession $session -Command "sed -i 's/enable_gro_gso:.*/enable_gro_gso: ""$Value""/' /etc/novavpn/server.yaml"
    } else {
        # Добавляем новую строку перед log_level
        $null = Invoke-SSHCommand -SSHSession $session -Command "sed -i '/^log_level:/i enable_gro_gso: ""$Value""' /etc/novavpn/server.yaml"
    }

    # Перезапускаем сервер
    $null = Invoke-SSHCommand -SSHSession $session -Command "systemctl restart novavpn"
    Start-Sleep -Seconds 3

    # Проверяем статус
    $r = Invoke-SSHCommand -SSHSession $session -Command "systemctl is-active novavpn"
    $status = ($r.Output | Out-String).Trim()
    if ($status -ne "active") {
        Write-Host "    [ОШИБКА] Сервер не запустился после перезапуска!" -ForegroundColor Red
        $r = Invoke-SSHCommand -SSHSession $session -Command "journalctl -u novavpn --no-pager -n 10"
        $r.Output | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        return $false
    }

    # Показываем GRO-логи из journalctl
    $r = Invoke-SSHCommand -SSHSession $session -Command "journalctl -u novavpn --no-pager -n 20 | grep -i 'GRO\|GSO\|USO\|VNET\|enable_gro'"
    if ($r.Output) {
        $r.Output | ForEach-Object {
            if ($_.Trim()) { Write-Host "    [LOG] $_" -ForegroundColor DarkCyan }
        }
    }

    return $true
}

# ═══════════════════════════════════════════════
#  5. Тест 1: GRO ВЫКЛЮЧЕН
# ═══════════════════════════════════════════════

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════" -ForegroundColor Red
Write-Host "   ФАЗА 1: GRO/GSO ВЫКЛЮЧЕН (enable_gro_gso: false)" -ForegroundColor Red
Write-Host "  ═══════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""

Write-Host "  [CONFIG] Отключаю GRO/GSO..." -ForegroundColor Yellow
$ok = Set-GROConfig "false"
if (-not $ok) {
    Remove-SSHSession -SSHSession $session | Out-Null
    exit 1
}
Write-Host "  [OK] Сервер перезапущен без GRO" -ForegroundColor Green
Write-Host ""

# Прогоняем тесты (throughput 1x, throughput 10x, rtt 10x)
$offResults = @{
    tp1  = Run-BenchTest "OFF" "throughput" 1  "/tmp/gro-off-tp1.json"
    tp10 = Run-BenchTest "OFF" "throughput" 10 "/tmp/gro-off-tp10.json"
    rtt10 = Run-BenchTest "OFF" "rtt" 10 "/tmp/gro-off-rtt10.json"
}

Start-Sleep -Seconds 3

# ═══════════════════════════════════════════════
#  6. Тест 2: GRO ВКЛЮЧЕН
# ═══════════════════════════════════════════════

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════" -ForegroundColor Green
Write-Host "   ФАЗА 2: GRO/GSO ВКЛЮЧЕН (enable_gro_gso: auto)" -ForegroundColor Green
Write-Host "  ═══════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

Write-Host "  [CONFIG] Включаю GRO/GSO..." -ForegroundColor Yellow
$ok = Set-GROConfig "auto"
if (-not $ok) {
    Remove-SSHSession -SSHSession $session | Out-Null
    exit 1
}
Write-Host "  [OK] Сервер перезапущен с GRO" -ForegroundColor Green
Write-Host ""

$onResults = @{
    tp1  = Run-BenchTest "ON" "throughput" 1  "/tmp/gro-on-tp1.json"
    tp10 = Run-BenchTest "ON" "throughput" 10 "/tmp/gro-on-tp10.json"
    rtt10 = Run-BenchTest "ON" "rtt" 10 "/tmp/gro-on-rtt10.json"
}

# ═══════════════════════════════════════════════
#  7. Сравнительная таблица
# ═══════════════════════════════════════════════

function Format-NS([double]$ns) {
    $ms = $ns / 1e6
    if ($ms -ge 1000)  { return "{0:F2}с" -f ($ms / 1000) }
    elseif ($ms -ge 1) { return "{0:F1}мс" -f $ms }
    else               { return "{0:F0}мкс" -f ($ms * 1000) }
}

function Format-Delta([double]$offVal, [double]$onVal) {
    if ($offVal -eq 0) { return "n/a" }
    $pct = (($onVal - $offVal) / $offVal) * 100
    if ($pct -gt 0) {
        return "+{0:F1}%" -f $pct
    } else {
        return "{0:F1}%" -f $pct
    }
}

function Get-DeltaColor([double]$offVal, [double]$onVal, [bool]$higherIsBetter = $true) {
    if ($offVal -eq 0) { return "DarkGray" }
    $pct = (($onVal - $offVal) / $offVal) * 100
    if ($higherIsBetter) {
        if ($pct -gt 3)   { return "Green" }
        elseif ($pct -lt -3) { return "Red" }
        else { return "DarkGray" }
    } else {
        if ($pct -lt -3)  { return "Green" }
        elseif ($pct -gt 3) { return "Red" }
        else { return "DarkGray" }
    }
}

Write-Host ""
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║                    СРАВНЕНИЕ GRO/GSO: ON vs OFF                                  ║" -ForegroundColor Magenta
Write-Host "  ╠═══════════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Magenta
Write-Host "  ║  Ядро: $($kernelVersion.PadRight(73))║" -ForegroundColor White
Write-Host "  ╚═══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# Заголовок таблицы
Write-Host ("  {0}  {1}  {2}  {3}" -f "Метрика".PadRight(26), "GRO OFF".PadRight(14), "GRO ON".PadRight(14), "Δ".PadRight(10)) -ForegroundColor White
Write-Host "  ─────────────────────────  ──────────────  ──────────────  ──────────" -ForegroundColor DarkGray

# --- Throughput 1x ---
if ($offResults.tp1 -and $onResults.tp1) {
    $offMbps = $offResults.tp1.mbits_per_sec
    $onMbps  = $onResults.tp1.mbits_per_sec
    $delta   = Format-Delta $offMbps $onMbps
    $dColor  = Get-DeltaColor $offMbps $onMbps $true
    Write-Host -NoNewline ("  {0}" -f "Throughput 1x (Мбит/с)".PadRight(28)) -ForegroundColor White
    Write-Host -NoNewline ("{0:F1}" -f $offMbps).PadRight(16) -ForegroundColor DarkGray
    Write-Host -NoNewline ("{0:F1}" -f $onMbps).PadRight(16) -ForegroundColor Cyan
    Write-Host $delta -ForegroundColor $dColor

    $offPps = $offResults.tp1.packets_per_sec
    $onPps  = $onResults.tp1.packets_per_sec
    $delta  = Format-Delta $offPps $onPps
    $dColor = Get-DeltaColor $offPps $onPps $true
    Write-Host -NoNewline ("  {0}" -f "  пакетов/сек".PadRight(28)) -ForegroundColor DarkGray
    Write-Host -NoNewline ("{0:N0}" -f $offPps).PadRight(16) -ForegroundColor DarkGray
    Write-Host -NoNewline ("{0:N0}" -f $onPps).PadRight(16) -ForegroundColor DarkGray
    Write-Host $delta -ForegroundColor $dColor
}

# --- Throughput 10x ---
if ($offResults.tp10 -and $onResults.tp10) {
    $offMbps = $offResults.tp10.mbits_per_sec
    $onMbps  = $onResults.tp10.mbits_per_sec
    $delta   = Format-Delta $offMbps $onMbps
    $dColor  = Get-DeltaColor $offMbps $onMbps $true
    Write-Host -NoNewline ("  {0}" -f "Throughput 10x (Мбит/с)".PadRight(28)) -ForegroundColor White
    Write-Host -NoNewline ("{0:F1}" -f $offMbps).PadRight(16) -ForegroundColor DarkGray
    Write-Host -NoNewline ("{0:F1}" -f $onMbps).PadRight(16) -ForegroundColor Cyan
    Write-Host $delta -ForegroundColor $dColor

    $offConn = $offResults.tp10.clients_total - $offResults.tp10.handshake_errors
    $onConn  = $onResults.tp10.clients_total - $onResults.tp10.handshake_errors
    Write-Host -NoNewline ("  {0}" -f "  подключения".PadRight(28)) -ForegroundColor DarkGray
    Write-Host -NoNewline ("$offConn/10").PadRight(16) -ForegroundColor DarkGray
    Write-Host -NoNewline ("$onConn/10").PadRight(16) -ForegroundColor DarkGray
    Write-Host "" -ForegroundColor DarkGray
}

Write-Host "  ─────────────────────────  ──────────────  ──────────────  ──────────" -ForegroundColor DarkGray

# --- RTT 10x ---
if ($offResults.rtt10 -and $onResults.rtt10) {
    if ($offResults.rtt10.rtt -and $onResults.rtt10.rtt) {
        $offP50 = $offResults.rtt10.rtt.p50_ns
        $onP50  = $onResults.rtt10.rtt.p50_ns
        $delta  = Format-Delta $offP50 $onP50
        $dColor = Get-DeltaColor $offP50 $onP50 $false  # lower is better
        Write-Host -NoNewline ("  {0}" -f "RTT p50 10x".PadRight(28)) -ForegroundColor White
        Write-Host -NoNewline (Format-NS $offP50).PadRight(16) -ForegroundColor DarkGray
        Write-Host -NoNewline (Format-NS $onP50).PadRight(16) -ForegroundColor Cyan
        Write-Host $delta -ForegroundColor $dColor

        $offP95 = $offResults.rtt10.rtt.p95_ns
        $onP95  = $onResults.rtt10.rtt.p95_ns
        $delta  = Format-Delta $offP95 $onP95
        $dColor = Get-DeltaColor $offP95 $onP95 $false
        Write-Host -NoNewline ("  {0}" -f "RTT p95 10x".PadRight(28)) -ForegroundColor White
        Write-Host -NoNewline (Format-NS $offP95).PadRight(16) -ForegroundColor DarkGray
        Write-Host -NoNewline (Format-NS $onP95).PadRight(16) -ForegroundColor Cyan
        Write-Host $delta -ForegroundColor $dColor

        $offP99 = $offResults.rtt10.rtt.p99_ns
        $onP99  = $onResults.rtt10.rtt.p99_ns
        $delta  = Format-Delta $offP99 $onP99
        $dColor = Get-DeltaColor $offP99 $onP99 $false
        Write-Host -NoNewline ("  {0}" -f "RTT p99 10x".PadRight(28)) -ForegroundColor White
        Write-Host -NoNewline (Format-NS $offP99).PadRight(16) -ForegroundColor DarkGray
        Write-Host -NoNewline (Format-NS $onP99).PadRight(16) -ForegroundColor Cyan
        Write-Host $delta -ForegroundColor $dColor
    }

    # Потери
    $offLoss = $offResults.rtt10.packet_loss_percent
    $onLoss  = $onResults.rtt10.packet_loss_percent
    Write-Host -NoNewline ("  {0}" -f "Потери 10x".PadRight(28)) -ForegroundColor White
    Write-Host -NoNewline ("{0:F2}%" -f $offLoss).PadRight(16) -ForegroundColor DarkGray
    Write-Host -NoNewline ("{0:F2}%" -f $onLoss).PadRight(16) -ForegroundColor Cyan
    Write-Host "" -ForegroundColor DarkGray
}

Write-Host "  ─────────────────────────  ──────────────  ──────────────  ──────────" -ForegroundColor DarkGray

# --- Handshake ---
if ($offResults.rtt10 -and $onResults.rtt10) {
    if ($offResults.rtt10.handshake -and $onResults.rtt10.handshake) {
        $offHS = $offResults.rtt10.handshake.avg_ns
        $onHS  = $onResults.rtt10.handshake.avg_ns
        $delta = Format-Delta $offHS $onHS
        $dColor = Get-DeltaColor $offHS $onHS $false
        Write-Host -NoNewline ("  {0}" -f "Handshake avg 10x".PadRight(28)) -ForegroundColor White
        Write-Host -NoNewline (Format-NS $offHS).PadRight(16) -ForegroundColor DarkGray
        Write-Host -NoNewline (Format-NS $onHS).PadRight(16) -ForegroundColor Cyan
        Write-Host $delta -ForegroundColor $dColor
    }
}

# ═══════════════════════════════════════════════
#  8. Вывод
# ═══════════════════════════════════════════════

Write-Host ""
Write-Host ""

# Определяем итог
$avgDelta = 0
$deltaCount = 0
if ($offResults.tp1 -and $onResults.tp1 -and $offResults.tp1.mbits_per_sec -gt 0) {
    $avgDelta += ($onResults.tp1.mbits_per_sec - $offResults.tp1.mbits_per_sec) / $offResults.tp1.mbits_per_sec * 100
    $deltaCount++
}
if ($offResults.tp10 -and $onResults.tp10 -and $offResults.tp10.mbits_per_sec -gt 0) {
    $avgDelta += ($onResults.tp10.mbits_per_sec - $offResults.tp10.mbits_per_sec) / $offResults.tp10.mbits_per_sec * 100
    $deltaCount++
}
if ($deltaCount -gt 0) { $avgDelta = $avgDelta / $deltaCount }

Write-Host "  ┌────────────────────────────────────────────────────────" -ForegroundColor Magenta
Write-Host "  │" -ForegroundColor Magenta
if ([math]::Abs($avgDelta) -lt 3) {
    Write-Host "  │  ВЫВОД: Разница в пределах погрешности (~±3%)" -ForegroundColor Yellow
    Write-Host "  │" -ForegroundColor Magenta
    Write-Host "  │  vpnbench тестирует путь client→server (UDP→TUN write)." -ForegroundColor DarkGray
    Write-Host "  │  GRO/GSO оптимизирует путь server→client (TUN read→UDP)." -ForegroundColor DarkGray
    Write-Host "  │  Реальный эффект GRO виден при TCP-трафике через VPN:" -ForegroundColor DarkGray
    Write-Host "  │  веб-сёрфинг, скачивание файлов, потоковое видео." -ForegroundColor DarkGray
} elseif ($avgDelta -gt 3) {
    Write-Host "  │  ВЫВОД: GRO даёт прирост throughput" -ForegroundColor Green
    Write-Host "  │  Средний прирост: $("{0:F1}" -f $avgDelta)%" -ForegroundColor Green
} else {
    Write-Host "  │  ВЫВОД: GRO вносит overhead (virtio header на каждый TUN write)" -ForegroundColor Red
    Write-Host "  │  Средний overhead: $("{0:F1}" -f [math]::Abs($avgDelta))%" -ForegroundColor Red
    Write-Host "  │" -ForegroundColor Magenta
    Write-Host "  │  Рекомендация: отключить GRO (enable_gro_gso: false)" -ForegroundColor Yellow
}
Write-Host "  │" -ForegroundColor Magenta
Write-Host "  │  Важно: GRO/GSO оптимизирует TUN read path (сервер→клиент)." -ForegroundColor DarkGray
Write-Host "  │  Для полной оценки нужен iperf3 через VPN-туннель." -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor Magenta
Write-Host "  └────────────────────────────────────────────────────────" -ForegroundColor Magenta

# ═══════════════════════════════════════════════
#  9. Восстановление и очистка
# ═══════════════════════════════════════════════

# Оставляем GRO включенным (auto) — это production-конфиг
$r = Invoke-SSHCommand -SSHSession $session -Command "grep 'enable_gro_gso' /etc/novavpn/server.yaml"
$currentGro = ($r.Output | Out-String).Trim()
Write-Host ""
Write-Host "[CONFIG] Текущая конфигурация: $currentGro" -ForegroundColor Cyan

Remove-SSHSession -SSHSession $session | Out-Null
Remove-Item $binaryPath -ErrorAction SilentlyContinue

Write-Host "[ГОТОВО] Бенчмарк GRO завершён" -ForegroundColor Green
Write-Host ""
