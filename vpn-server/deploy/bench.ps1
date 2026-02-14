<#
.SYNOPSIS
    Запуск нагрузочного теста NovaVPN на удалённом сервере.

.DESCRIPTION
    Кросс-компилирует vpnbench под Linux, загружает на сервер по SCP,
    запускает по SSH (localhost), выводит результаты.

    Конфигурация: deploy-config.json (рядом со скриптом).
    Зависимость: модуль Posh-SSH (устанавливается автоматически).

.PARAMETER clients
    Количество одновременных клиентов (по умолчанию: 10)

.PARAMETER duration
    Длительность теста (по умолчанию: 30s)

.PARAMETER interval
    Интервал keepalive пакетов (по умолчанию: 100ms)

.PARAMETER mode
    Режим: rtt (keepalive RTT) или throughput (data flood) (по умолчанию: rtt)

.EXAMPLE
    .\bench.ps1
    .\bench.ps1 -clients 50 -duration 60s -interval 50ms
    .\bench.ps1 -mode throughput -clients 1 -duration 15s
#>

param(
    [int]$clients = 10,
    [string]$duration = "30s",
    [string]$interval = "100ms",
    [string]$mode = "rtt"
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
Write-Host "  ══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "    NovaVPN Benchmark Runner" -ForegroundColor Cyan
Write-Host "  ══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Сервер:      $sshUser@${sshHost}" -ForegroundColor White
Write-Host "  Клиенты:     $clients" -ForegroundColor White
Write-Host "  Время:       $duration" -ForegroundColor White
Write-Host "  Интервал:    $interval" -ForegroundColor White
Write-Host "  Режим:       $mode" -ForegroundColor White
Write-Host "  ══════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════════
#  2. Проверка / установка Posh-SSH
# ═══════════════════════════════════════════════

if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Host "[SSH] Модуль Posh-SSH не установлен. Устанавливаю..." -ForegroundColor Yellow
    Install-Module -Name Posh-SSH -Force -Scope CurrentUser -AllowClobber
    Write-Host "[SSH] Posh-SSH установлен" -ForegroundColor Green
}
Import-Module Posh-SSH -ErrorAction Stop

# ═══════════════════════════════════════════════
#  3. Сборка vpnbench (Linux amd64)
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
#  4. Подключение по SSH
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

# ═══════════════════════════════════════════════
#  5. Загрузка бинарника на сервер
# ═══════════════════════════════════════════════

Write-Host "[SCP] Загрузка vpnbench на сервер..." -ForegroundColor Cyan

Set-SCPItem -ComputerName $sshHost -Port $sshPort -Credential $cred `
    -Path $binaryPath -Destination "/tmp/" -AcceptKey -Force

$r = Invoke-SSHCommand -SSHSession $session -Command "chmod +x /tmp/vpnbench"
Write-Host "[SCP] Загружено" -ForegroundColor Green

# ═══════════════════════════════════════════════
#  6. Получение PSK с сервера
# ═══════════════════════════════════════════════

Write-Host "[CONFIG] Читаю PSK из конфигурации сервера..." -ForegroundColor Cyan

$r = Invoke-SSHCommand -SSHSession $session -Command "grep pre_shared_key /etc/novavpn/server.yaml | awk -F'""' '{print `$2}'"
$psk = $r.Output.Trim()

if (-not $psk -or $psk.Length -ne 64) {
    Write-Host "[ОШИБКА] Не удалось получить PSK (длина: $($psk.Length))" -ForegroundColor Red
    Remove-SSHSession -SSHSession $session | Out-Null
    exit 1
}
Write-Host "[CONFIG] PSK получен ($($psk.Substring(0,8))...)" -ForegroundColor Green

# ═══════════════════════════════════════════════
#  7. Запуск бенчмарка
# ═══════════════════════════════════════════════

Write-Host ""
Write-Host "[BENCH] Запуск нагрузочного теста..." -ForegroundColor Yellow
Write-Host "[BENCH] $clients клиентов × $duration × режим $mode" -ForegroundColor Yellow
Write-Host ""

$benchCmd = "/tmp/vpnbench " +
    "-server 127.0.0.1:$vpnPort " +
    "-psk '$psk' " +
    "-email '$testEmail' " +
    "-password '$testPassword' " +
    "-clients $clients " +
    "-duration $duration " +
    "-interval $interval " +
    "-mode $mode " +
    "-json /tmp/bench-result.json " +
    "2>&1"

# Таймаут: длительность теста + 2 минуты на handshake
# Парсим длительность для расчёта таймаута
$durationSec = 30
if ($duration -match '^(\d+)s$') { $durationSec = [int]$Matches[1] }
elseif ($duration -match '^(\d+)m$') { $durationSec = [int]$Matches[1] * 60 }
$timeoutSec = $durationSec + 120

$r = Invoke-SSHCommand -SSHSession $session -Command $benchCmd -TimeOut $timeoutSec

# ═══════════════════════════════════════════════
#  8. Вывод результатов
# ═══════════════════════════════════════════════

if ($r.Output) {
    $r.Output | ForEach-Object {
        $line = $_
        if ($line -match '═') {
            Write-Host $line -ForegroundColor Cyan
        } elseif ($line -match '──') {
            Write-Host $line -ForegroundColor DarkCyan
        } elseif ($line -match '\[ОШИБКА\]|ошибок подключения: [1-9]') {
            Write-Host $line -ForegroundColor Red
        } elseif ($line -match '\[CLIENT-') {
            Write-Host $line -ForegroundColor DarkGray
        } elseif ($line -match '\[BENCH\]') {
            Write-Host $line -ForegroundColor Yellow
        } elseif ($line -match 'Потери:\s+0\.00%') {
            Write-Host $line -ForegroundColor Green
        } elseif ($line -match 'Потери:\s+[1-9]') {
            Write-Host $line -ForegroundColor Red
        } else {
            Write-Host $line
        }
    }
}

if ($r.ExitStatus -ne 0) {
    Write-Host ""
    Write-Host "[ОШИБКА] Бенчмарк завершился с ошибкой (exit code: $($r.ExitStatus))" -ForegroundColor Red
}

# ═══════════════════════════════════════════════
#  9. Скачиваем JSON-отчёт
# ═══════════════════════════════════════════════

$localJsonPath = Join-Path $projectDir "bench-result.json"

try {
    Get-SCPItem -ComputerName $sshHost -Port $sshPort -Credential $cred `
        -Path "/tmp/bench-result.json" -PathType File -Destination $projectDir -AcceptKey -Force

    Write-Host ""
    Write-Host "[OK] JSON-отчёт сохранён: $localJsonPath" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Не удалось скачать JSON-отчёт: $_" -ForegroundColor Yellow
}

# ═══════════════════════════════════════════════
#  10. Очистка
# ═══════════════════════════════════════════════

Remove-SSHSession -SSHSession $session | Out-Null
Remove-Item $binaryPath -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[ГОТОВО] Бенчмарк завершён" -ForegroundColor Green
