<#
.SYNOPSIS
    NovaVPN — Stress-тест сервера (определение максимума клиентов).

.DESCRIPTION
    Ступенчато наращивает количество одновременных VPN-клиентов (10 → 35 → 60 → ... → 200),
    каждый клиент генерирует реалистичный трафик (keepalive + burst data).
    Тест автоматически останавливается при деградации.

    Результат: "сервер стабильно тянет N одновременных клиентов".

    Конфигурация: deploy-config.json (рядом со скриптом).

.PARAMETER stepDuration
    Длительность каждой ступени (по умолчанию: 15s)

.PARAMETER maxClients
    Потолок клиентов (по умолчанию: 2000)

.PARAMETER step
    Шаг увеличения (по умолчанию: 25)

.EXAMPLE
    .\bench-stress.ps1
    .\bench-stress.ps1 -maxClients 150 -step 10
    .\bench-stress.ps1 -stepDuration 30s
#>

param(
    [string]$stepDuration = "15s",
    [int]$maxClients = 2000,
    [int]$step = 25,
    [int]$start = 10
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

# Рассчитываем количество ступеней и общее время
$stepsCount = [math]::Ceiling(($maxClients - $start) / $step) + 1
$stepDurSec = 15
if ($stepDuration -match '^(\d+)s$') { $stepDurSec = [int]$Matches[1] }
elseif ($stepDuration -match '^(\d+)m$') { $stepDurSec = [int]$Matches[1] * 60 }
$estimatedMinutes = [math]::Ceiling($stepsCount * ($stepDurSec + 15) / 60)  # +15 на handshake

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║    NovaVPN — STRESS TEST (макс. клиентов)     ║" -ForegroundColor Magenta
Write-Host "  ╠═══════════════════════════════════════════════╣" -ForegroundColor Magenta
Write-Host ("  ║  Сервер:    {0}@{1}" -f $sshUser, $sshHost).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
Write-Host ("  ║  Старт:     {0} клиентов" -f $start).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
Write-Host ("  ║  Шаг:       +{0} клиентов" -f $step).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
Write-Host ("  ║  Потолок:   {0} клиентов" -f $maxClients).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
Write-Host ("  ║  Ступеней:  ~{0} (по {1})" -f $stepsCount, $stepDuration).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
Write-Host ("  ║  ~Время:    ~{0} мин" -f $estimatedMinutes).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
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
#  4. SSH + деплой
# ═══════════════════════════════════════════════

Write-Host "[SSH] Подключение к $sshHost..." -ForegroundColor Cyan

$secPass  = ConvertTo-SecureString $sshPass -AsPlainText -Force
$cred     = New-Object System.Management.Automation.PSCredential($sshUser, $secPass)
$session  = New-SSHSession -ComputerName $sshHost -Port $sshPort -Credential $cred -AcceptKey -Force

if (-not $session -or -not $session.Connected) {
    Write-Host "[ОШИБКА] Не удалось подключиться к серверу" -ForegroundColor Red
    exit 1
}
Write-Host "[SSH] Подключено" -ForegroundColor Green

Write-Host "[SCP] Загрузка vpnbench..." -ForegroundColor Cyan
Set-SCPItem -ComputerName $sshHost -Port $sshPort -Credential $cred `
    -Path $binaryPath -Destination "/tmp/" -AcceptKey -Force
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

# ═══════════════════════════════════════════════
#  5. Запуск stress-теста
# ═══════════════════════════════════════════════

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "   ЗАПУСК STRESS-ТЕСТА..." -ForegroundColor Magenta
Write-Host "  ═══════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host ""

$jsonFile = "/tmp/stress-result.json"

$benchCmd = "/tmp/vpnbench " +
    "-server 127.0.0.1:$vpnPort " +
    "-psk '$psk' " +
    "-email '$testEmail' " +
    "-password '$testPassword' " +
    "-mode stress " +
    "-stress-start $start " +
    "-stress-step $step " +
    "-stress-max $maxClients " +
    "-stress-step-duration $stepDuration " +
    "-stress-burst-interval 300ms " +
    "-stress-burst-size 5 " +
    "-json $jsonFile " +
    "2>&1"

# Таймаут: ступени * (stepDur + handshake-overhead + margin)
$timeoutSec = $stepsCount * ($stepDurSec + 30) + 120

Write-Host "[RUN] Таймаут: ${timeoutSec}с" -ForegroundColor DarkGray

$r = Invoke-SSHCommand -SSHSession $session -Command $benchCmd -TimeOut $timeoutSec

# Выводим вывод
if ($r.Output) {
    $r.Output | ForEach-Object {
        $line = $_
        if ($line -match 'FAILED|❌') {
            Write-Host "    $line" -ForegroundColor Red
        } elseif ($line -match 'DEGRADED|⚠') {
            Write-Host "    $line" -ForegroundColor Yellow
        } elseif ($line -match '✅|OK|ВЕРДИКТ|стабильн') {
            Write-Host "    $line" -ForegroundColor Green
        } elseif ($line -match '═|╔|╗|╠|╣|╚|╝|║|──|STRESS|ИТОГ') {
            Write-Host "    $line" -ForegroundColor Cyan
        } elseif ($line -match 'СТУПЕНЬ|CONNECT|MEASURE|CLEANUP|STOP') {
            Write-Host "    $line" -ForegroundColor Magenta
        } elseif ($line -match 'Результат:|Подключения:|Handshake:|RTT:|Keepalive:|Data|Причина:') {
            Write-Host "    $line" -ForegroundColor White
        } else {
            Write-Host "    $line" -ForegroundColor DarkGray
        }
    }
}

# ═══════════════════════════════════════════════
#  6. Получаем JSON-результат
# ═══════════════════════════════════════════════

$jr = Invoke-SSHCommand -SSHSession $session -Command "cat $jsonFile 2>/dev/null"
$stressResult = $null
if ($jr.Output) {
    try {
        $stressResult = ($jr.Output | Out-String | ConvertFrom-Json)
    } catch {
        Write-Host "[WARN] Не удалось прочитать JSON-результат" -ForegroundColor Yellow
    }
}

# ═══════════════════════════════════════════════
#  7. Итоговая сводка
# ═══════════════════════════════════════════════

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║              STRESS TEST — ИТОГ                          ║" -ForegroundColor Magenta
Write-Host "  ╠═══════════════════════════════════════════════════════════╣" -ForegroundColor Magenta

if ($stressResult) {
    $maxStable = $stressResult.max_stable_clients
    $maxTested = $stressResult.max_tested_clients
    $stopReason = $stressResult.stop_reason
    $totalDur = $stressResult.total_duration

    $color = "Green"
    if ($maxStable -lt 50) { $color = "Red" }
    elseif ($maxStable -lt 100) { $color = "Yellow" }

    Write-Host ("  ║  Макс. стабильных:  {0} клиентов" -f $maxStable).PadRight(60) -NoNewline -ForegroundColor $color; Write-Host "║" -ForegroundColor Magenta
    Write-Host ("  ║  Протестировано:     {0} клиентов" -f $maxTested).PadRight(60) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
    Write-Host ("  ║  Время:             {0}" -f $totalDur).PadRight(60) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Magenta
    Write-Host ("  ║  Причина остановки: {0}" -f $stopReason).PadRight(60) -NoNewline -ForegroundColor DarkYellow; Write-Host "║" -ForegroundColor Magenta

    # Таблица ступеней
    if ($stressResult.steps) {
        Write-Host "  ╠═══════════════════════════════════════════════════════════╣" -ForegroundColor Magenta
        Write-Host "  ║  Клиенты  Подкл  HS avg     RTT p50   KA потери  Статус  ║" -ForegroundColor Magenta
        Write-Host "  ║  ───────  ─────  ─────────  ────────  ─────────  ──────  ║" -ForegroundColor Magenta

        foreach ($s in $stressResult.steps) {
            $tc = $s.target_clients
            $cc = $s.connected_clients
            $hsAvg = $s.handshake_avg
            $rttP50 = if ($s.rtt.p50) { $s.rtt.p50 } else { "—" }
            $kaLoss = if ($s.keepalive_sent -gt 0) { "{0:F1}%" -f $s.keepalive_loss_percent } else { "—" }
            $status = $s.status

            $icon = "✅"
            $sColor = "Green"
            if ($status -eq "DEGRADED") { $icon = "⚠️"; $sColor = "Yellow" }
            if ($status -eq "FAILED") { $icon = "❌"; $sColor = "Red" }

            $line = ("  ║  {0,4}     {1,4}   {2,-9}  {3,-8}  {4,-9}  {5}  " -f $tc, $cc, $hsAvg, $rttP50, $kaLoss, $icon)
            Write-Host $line.PadRight(60) -NoNewline -ForegroundColor $sColor; Write-Host "║" -ForegroundColor Magenta
        }
    }
} else {
    Write-Host "  ║  Результат недоступен (JSON не получен)                   ║" -ForegroundColor Red
}

Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

# ═══════════════════════════════════════════════
#  8. Очистка
# ═══════════════════════════════════════════════

Remove-SSHSession -SSHSession $session | Out-Null
Remove-Item $binaryPath -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[ГОТОВО] Stress-тест завершён" -ForegroundColor Green
Write-Host ""
