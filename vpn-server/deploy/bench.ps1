<#
.SYNOPSIS
    Полный бенчмарк NovaVPN — автоматический многорежимный тест сервера.

.DESCRIPTION
    1. Кросс-компилирует vpnbench под Linux и загружает на сервер
    2. Последовательно прогоняет серию тестов:
       - Throughput (1 клиент, data flood) — пропускная способность
       - Throughput (10 клиентов, data flood) — пропускная способность под нагрузкой
       - RTT (1 клиент) — задержка
       - RTT (10 клиентов) — задержка под нагрузкой
       - RTT (50 клиентов) — масштабируемость
    3. Выводит сводную таблицу с рейтингом и сравнением с OpenVPN/WireGuard

    Конфигурация: deploy-config.json (рядом со скриптом).
    Зависимость: модуль Posh-SSH (устанавливается автоматически).

.PARAMETER quick
    Быстрый режим — только 3 теста вместо 5 (по умолчанию: false)

.PARAMETER duration
    Длительность каждого теста (по умолчанию: 15s)

.EXAMPLE
    .\bench.ps1
    .\bench.ps1 -quick
    .\bench.ps1 -duration 30s
#>

param(
    [switch]$quick,
    [string]$duration = "15s"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir

# ═══════════════════════════════════════════════════════
#  Конфигурация тестовых сценариев
# ═══════════════════════════════════════════════════════

$testScenarios = @(
    @{ Name = "Throughput 1x клиент";   Mode = "throughput"; Clients = 1;  Interval = "100ms"; Desc = "Макс. пропускная способность" }
    @{ Name = "Throughput 10x клиент";  Mode = "throughput"; Clients = 10; Interval = "100ms"; Desc = "Пропускная под нагрузкой" }
    @{ Name = "RTT 1x клиент";          Mode = "rtt";        Clients = 1;  Interval = "50ms";  Desc = "Задержка (одиночный)" }
    @{ Name = "RTT 10x клиентов";       Mode = "rtt";        Clients = 10; Interval = "100ms"; Desc = "Задержка (средняя нагрузка)" }
    @{ Name = "RTT 50x клиентов";       Mode = "rtt";        Clients = 50; Interval = "100ms"; Desc = "Масштабируемость" }
)

if ($quick) {
    # Быстрый режим: throughput x1, rtt x1, rtt x10
    $testScenarios = @(
        @{ Name = "Throughput 1x клиент"; Mode = "throughput"; Clients = 1;  Interval = "100ms"; Desc = "Макс. пропускная способность" }
        @{ Name = "RTT 1x клиент";        Mode = "rtt";        Clients = 1;  Interval = "50ms";  Desc = "Задержка (одиночный)" }
        @{ Name = "RTT 10x клиентов";     Mode = "rtt";        Clients = 10; Interval = "100ms"; Desc = "Задержка (средняя нагрузка)" }
    )
}

# ═══════════════════════════════════════════════════════
#  Эталонные значения VPN систем (localhost, типичные)
# ═══════════════════════════════════════════════════════
#
# Источники:
#   WireGuard: ~900-1000 Мбит/с localhost, RTT p50 ~50мкс
#   OpenVPN (UDP): ~150-300 Мбит/с localhost, RTT p50 ~200-500мкс
#   IPsec/IKEv2: ~400-600 Мбит/с localhost, RTT p50 ~100-200мкс
#   OpenConnect: ~200-400 Мбит/с localhost, RTT p50 ~150-300мкс
#
# Шкала оценок NovaVPN:
#   Throughput: <100=Плохо | 100-300=Нормально | 300-600=Хорошо | >600=Отлично
#   RTT p50:    >1мс=Плохо | 500мкс-1мс=Нормально | 100-500мкс=Хорошо | <100мкс=Отлично
#   Потери:     >5%=Плохо | 1-5%=Нормально | 0.1-1%=Хорошо | <0.1%=Отлично
#   Handshake:  >5с=Плохо | 2-5с=Нормально | 500мс-2с=Хорошо | <500мс=Отлично
#   Масштаб:    <50%=Плохо | 50-80%=Нормально | 80-95%=Хорошо | >95%=Отлично

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

$totalTests = $testScenarios.Count
$modeLabel = if ($quick) { "быстрый ($totalTests теста)" } else { "полный ($totalTests тестов)" }

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║      NovaVPN — Полный бенчмарк сервера        ║" -ForegroundColor Cyan
Write-Host "  ╠═══════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host ("  ║  Сервер:    {0}@{1}" -f $sshUser, $sshHost).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Cyan
Write-Host ("  ║  Режим:     {0}" -f $modeLabel).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Cyan
Write-Host ("  ║  Время:     {0} на каждый тест" -f $duration).PadRight(50) -NoNewline -ForegroundColor White; Write-Host "║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Cyan
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
#  4. Подключение по SSH и деплой бенчмарка
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

Write-Host "[SCP] Загрузка vpnbench на сервер..." -ForegroundColor Cyan

Set-SCPItem -ComputerName $sshHost -Port $sshPort -Credential $cred `
    -Path $binaryPath -Destination "/tmp/" -AcceptKey -Force

$null = Invoke-SSHCommand -SSHSession $session -Command "chmod +x /tmp/vpnbench"
Write-Host "[SCP] Бенчмарк загружен на сервер" -ForegroundColor Green

# Получаем PSK
Write-Host "[CONFIG] Читаю PSK из конфигурации сервера..." -ForegroundColor Cyan
$r = Invoke-SSHCommand -SSHSession $session -Command "grep pre_shared_key /etc/novavpn/server.yaml | awk -F'""' '{print `$2}'"
$psk = $r.Output.Trim()

if (-not $psk -or $psk.Length -ne 64) {
    Write-Host "[ОШИБКА] Не удалось получить PSK (длина: $($psk.Length))" -ForegroundColor Red
    Remove-SSHSession -SSHSession $session | Out-Null
    exit 1
}
Write-Host "[CONFIG] PSK получен ($($psk.Substring(0,8))...)" -ForegroundColor Green

# ═══════════════════════════════════════════════════════
#  5. Последовательный запуск тестов
# ═══════════════════════════════════════════════════════

# Парсим длительность для расчёта таймаута
$durationSec = 30
if ($duration -match '^(\d+)s$') { $durationSec = [int]$Matches[1] }
elseif ($duration -match '^(\d+)m$') { $durationSec = [int]$Matches[1] * 60 }

$allResults = @()  # Массив JSON-отчётов
$testNum = 0

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "   Запуск $totalTests тестов (каждый по $duration)..." -ForegroundColor Yellow
Write-Host "  ═══════════════════════════════════════════════" -ForegroundColor Yellow

foreach ($scenario in $testScenarios) {
    $testNum++
    $sName     = $scenario.Name
    $sMode     = $scenario.Mode
    $sClients  = $scenario.Clients
    $sInterval = $scenario.Interval
    $sDesc     = $scenario.Desc

    Write-Host ""
    Write-Host "  ┌───────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host ("  │  Тест {0}/{1}: {2}" -f $testNum, $totalTests, $sName).PadRight(50) -NoNewline -ForegroundColor Yellow; Write-Host "│" -ForegroundColor Yellow
    Write-Host ("  │  {0}" -f $sDesc).PadRight(50) -NoNewline -ForegroundColor DarkYellow; Write-Host "│" -ForegroundColor Yellow
    Write-Host ("  │  режим={0}  клиенты={1}  время={2}" -f $sMode, $sClients, $duration).PadRight(50) -NoNewline -ForegroundColor DarkYellow; Write-Host "│" -ForegroundColor Yellow
    Write-Host "  └───────────────────────────────────────────────┘" -ForegroundColor Yellow

    $jsonFile = "/tmp/bench-$testNum.json"
    $benchCmd = "/tmp/vpnbench " +
        "-server 127.0.0.1:$vpnPort " +
        "-psk '$psk' " +
        "-email '$testEmail' " +
        "-password '$testPassword' " +
        "-clients $sClients " +
        "-duration $duration " +
        "-interval $sInterval " +
        "-mode $sMode " +
        "-json $jsonFile " +
        "2>&1"

    $timeoutSec = $durationSec + 120

    $r = Invoke-SSHCommand -SSHSession $session -Command $benchCmd -TimeOut $timeoutSec

    # Выводим результат компактно — только ключевые строки
    if ($r.Output) {
        $r.Output | ForEach-Object {
            $line = $_
            if ($line -match '^\s*(Min|Avg|P50|P95|P99|Max|Кол-во|Отправлено|Получено|Потери|Скорость|Handshake|Ошибки):') {
                Write-Host "    $line" -ForegroundColor White
            } elseif ($line -match '──') {
                Write-Host "    $line" -ForegroundColor DarkCyan
            } elseif ($line -match '\[CLIENT-') {
                # Выводим только первый и последний клиент
                if ($line -match 'CLIENT-0\]' -or $line -match "CLIENT-$($sClients-1)\]") {
                    Write-Host "    $line" -ForegroundColor DarkGray
                }
            } elseif ($line -match 'подключились|завершили') {
                Write-Host "    $line" -ForegroundColor Cyan
            } elseif ($line -match '\[ОШИБКА\]|ошибок подключения: [1-9]') {
                Write-Host "    $line" -ForegroundColor Red
            }
        }
    }

    # Читаем JSON-отчёт
    $jr = Invoke-SSHCommand -SSHSession $session -Command "cat $jsonFile 2>/dev/null"
    if ($jr.Output) {
        try {
            $reportJson = $jr.Output | Out-String | ConvertFrom-Json
            $allResults += @{
                Name      = $sName
                Mode      = $sMode
                Clients   = $sClients
                Report    = $reportJson
                ExitCode  = $r.ExitStatus
            }
        } catch {
            Write-Host "    [WARN] Не удалось прочитать JSON-отчёт" -ForegroundColor Yellow
        }
    }

    # Пауза 3с между тестами (дать серверу остыть)
    if ($testNum -lt $totalTests) {
        Write-Host "    ...пауза 3 сек..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 3
    }
}

# ═══════════════════════════════════════════════════════════
#  6. Финальная сводная таблица
# ═══════════════════════════════════════════════════════════

Write-Host ""
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                      СВОДНЫЕ РЕЗУЛЬТАТЫ БЕНЧМАРКА                                ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# --- Функции оценки ---

function Get-ThroughputRating([double]$mbps) {
    if     ($mbps -ge 600) { return @{ Grade = "ОТЛИЧНО"; Color = "Green";      Bar = "█████" } }
    elseif ($mbps -ge 300) { return @{ Grade = "ХОРОШО";  Color = "DarkGreen";  Bar = "████░" } }
    elseif ($mbps -ge 100) { return @{ Grade = "НОРМ";    Color = "Yellow";     Bar = "███░░" } }
    else                   { return @{ Grade = "ПЛОХО";   Color = "Red";        Bar = "██░░░" } }
}

function Get-RttRating([double]$p50us) {
    # p50 в микросекундах
    if     ($p50us -le 100)  { return @{ Grade = "ОТЛИЧНО"; Color = "Green";      Bar = "█████" } }
    elseif ($p50us -le 500)  { return @{ Grade = "ХОРОШО";  Color = "DarkGreen";  Bar = "████░" } }
    elseif ($p50us -le 1000) { return @{ Grade = "НОРМ";    Color = "Yellow";     Bar = "███░░" } }
    else                     { return @{ Grade = "ПЛОХО";   Color = "Red";        Bar = "██░░░" } }
}

function Get-LossRating([double]$pct) {
    if     ($pct -le 0.1) { return @{ Grade = "ОТЛИЧНО"; Color = "Green";      Bar = "█████" } }
    elseif ($pct -le 1.0) { return @{ Grade = "ХОРОШО";  Color = "DarkGreen";  Bar = "████░" } }
    elseif ($pct -le 5.0) { return @{ Grade = "НОРМ";    Color = "Yellow";     Bar = "███░░" } }
    else                  { return @{ Grade = "ПЛОХО";   Color = "Red";        Bar = "██░░░" } }
}

function Get-HandshakeRating([double]$ms) {
    if     ($ms -le 500)  { return @{ Grade = "ОТЛИЧНО"; Color = "Green";      Bar = "█████" } }
    elseif ($ms -le 2000) { return @{ Grade = "ХОРОШО";  Color = "DarkGreen";  Bar = "████░" } }
    elseif ($ms -le 5000) { return @{ Grade = "НОРМ";    Color = "Yellow";     Bar = "███░░" } }
    else                  { return @{ Grade = "ПЛОХО";   Color = "Red";        Bar = "██░░░" } }
}

function Get-ScaleRating([int]$clients, [int]$connected) {
    $pct = if ($clients -gt 0) { [math]::Round($connected / $clients * 100) } else { 0 }
    if     ($pct -ge 95) { return @{ Grade = "ОТЛИЧНО"; Color = "Green";      Bar = "█████" } }
    elseif ($pct -ge 80) { return @{ Grade = "ХОРОШО";  Color = "DarkGreen";  Bar = "████░" } }
    elseif ($pct -ge 50) { return @{ Grade = "НОРМ";    Color = "Yellow";     Bar = "███░░" } }
    else                 { return @{ Grade = "ПЛОХО";   Color = "Red";        Bar = "██░░░" } }
}

function Format-Duration([double]$ns) {
    $ms = $ns / 1e6
    if ($ms -ge 1000)  { return "{0:F2} с" -f ($ms / 1000) }
    elseif ($ms -ge 1) { return "{0:F1} мс" -f $ms }
    else               { return "{0:F0} мкс" -f ($ms * 1000) }
}

# --- Вывод результатов по каждому тесту ---

foreach ($result in $allResults) {
    $rep = $result.Report

    Write-Host "  ┌─── $($result.Name) ────────────────────────────────" -ForegroundColor White
    Write-Host "  │" -ForegroundColor DarkGray

    $connected = $result.Clients - $rep.handshake_errors
    Write-Host -NoNewline "  │  Подключения:  " -ForegroundColor DarkGray
    $connColor = if ($connected -eq $result.Clients) { "Green" } else { "Yellow" }
    Write-Host "$connected/$($result.Clients)" -ForegroundColor $connColor

    if ($rep.handshake -and $rep.handshake.count -gt 0) {
        $hsAvgMs = $rep.handshake.avg_ns / 1e6
        $hsR = Get-HandshakeRating $hsAvgMs
        Write-Host -NoNewline "  │  Handshake:    " -ForegroundColor DarkGray
        Write-Host -NoNewline ("avg={0}" -f (Format-Duration $rep.handshake.avg_ns)).PadRight(16) -ForegroundColor White
        Write-Host -NoNewline "$($hsR.Bar) " -ForegroundColor $hsR.Color
        Write-Host "$($hsR.Grade)" -ForegroundColor $hsR.Color
    }

    if ($result.Mode -eq "throughput") {
        $mbps = $rep.mbits_per_sec
        $tR = Get-ThroughputRating $mbps
        Write-Host -NoNewline "  │  Throughput:   " -ForegroundColor DarkGray
        Write-Host -NoNewline ("{0:F1} Мбит/с" -f $mbps).PadRight(16) -ForegroundColor White
        Write-Host -NoNewline "$($tR.Bar) " -ForegroundColor $tR.Color
        Write-Host "$($tR.Grade)" -ForegroundColor $tR.Color

        Write-Host -NoNewline "  │  Пакеты:      " -ForegroundColor DarkGray
        Write-Host ("{0:N0} пак/с  (отправлено {1:N0})" -f $rep.packets_per_sec, $rep.total_packets_sent) -ForegroundColor DarkGray
    }

    if ($result.Mode -eq "rtt" -and $rep.rtt -and $rep.rtt.count -gt 0) {
        $p50ns = $rep.rtt.p50_ns
        $p50us = $p50ns / 1000.0
        $rttR = Get-RttRating $p50us
        Write-Host -NoNewline "  │  RTT p50:      " -ForegroundColor DarkGray
        Write-Host -NoNewline (Format-Duration $p50ns).PadRight(16) -ForegroundColor White
        Write-Host -NoNewline "$($rttR.Bar) " -ForegroundColor $rttR.Color
        Write-Host "$($rttR.Grade)" -ForegroundColor $rttR.Color

        Write-Host -NoNewline "  │  RTT p95/p99:  " -ForegroundColor DarkGray
        Write-Host ("{0} / {1}" -f (Format-Duration $rep.rtt.p95_ns), (Format-Duration $rep.rtt.p99_ns)) -ForegroundColor DarkGray
    }

    # Потери: показываем только для RTT (throughput однонаправленный)
    if ($result.Mode -eq "rtt") {
        $lossPct = $rep.packet_loss_percent
        if ($null -ne $lossPct) {
            $lR = Get-LossRating $lossPct
            Write-Host -NoNewline "  │  Потери:       " -ForegroundColor DarkGray
            Write-Host -NoNewline ("{0:F2}%" -f $lossPct).PadRight(16) -ForegroundColor White
            Write-Host -NoNewline "$($lR.Bar) " -ForegroundColor $lR.Color
            Write-Host "$($lR.Grade)" -ForegroundColor $lR.Color
        }
    }

    Write-Host "  │" -ForegroundColor DarkGray
}

# --- Сбор ключевых метрик для общей оценки ---

$bestThroughput  = 0
$bestRttP50us    = [double]::MaxValue
$maxClients      = 0
$maxConnected    = 0
$bestHsMs        = [double]::MaxValue
$worstLoss       = 0

foreach ($result in $allResults) {
    $rep = $result.Report

    if ($result.Mode -eq "throughput" -and $rep.mbits_per_sec -gt $bestThroughput) {
        $bestThroughput = $rep.mbits_per_sec
    }

    if ($result.Mode -eq "rtt" -and $rep.rtt -and $rep.rtt.count -gt 0) {
        $p50us = $rep.rtt.p50_ns / 1000.0
        if ($p50us -lt $bestRttP50us) { $bestRttP50us = $p50us }
    }

    $connected = $result.Clients - $rep.handshake_errors
    if ($result.Clients -gt $maxClients) {
        $maxClients = $result.Clients
        $maxConnected = $connected
    }

    if ($rep.handshake -and $rep.handshake.count -gt 0) {
        $hsMs = $rep.handshake.avg_ns / 1e6
        if ($result.Clients -le 1 -and $hsMs -lt $bestHsMs) { $bestHsMs = $hsMs }
    }

    # Потери: учитываем только RTT-тесты (throughput однонаправленный, потери всегда 100%)
    if ($result.Mode -eq "rtt" -and $rep.packet_loss_percent -gt $worstLoss) {
        $worstLoss = $rep.packet_loss_percent
    }
}

if ($bestRttP50us -eq [double]::MaxValue) { $bestRttP50us = 0 }
if ($bestHsMs -eq [double]::MaxValue) { $bestHsMs = 0 }

# ═══════════════════════════════════════════════════════════
#  7. Сравнение с другими VPN
# ═══════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║                 СРАВНЕНИЕ С ДРУГИМИ VPN (localhost, типичные)                     ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Throughput (1 клиент, UDP, userspace — кроме WireGuard/IPsec):" -ForegroundColor DarkGray
Write-Host ""

# Таблица сравнения
$vpnComparison = @(
    @{ Name = "WireGuard";     Mbps = 900;  RttUs = 50;  Note = "Kernel-space, минимальный overhead" }
    @{ Name = "NovaVPN";       Mbps = [math]::Round($bestThroughput); RttUs = [math]::Round($bestRttP50us); Note = "Наш результат (со stealth)" }
    @{ Name = "IPsec/IKEv2";   Mbps = 500;  RttUs = 150; Note = "Kernel-space, стандартный" }
    @{ Name = "Shadowsocks";   Mbps = 350;  RttUs = 300; Note = "Прокси, без TUN overhead" }
    @{ Name = "OpenConnect";   Mbps = 300;  RttUs = 200; Note = "Userspace, DTLS" }
    @{ Name = "OpenVPN (UDP)"; Mbps = 200;  RttUs = 400; Note = "Userspace, OpenSSL" }
    @{ Name = "SoftEther";     Mbps = 150;  RttUs = 500; Note = "Userspace, многопротокольный" }
)

# Сортируем по throughput (убывание)
$vpnComparison = $vpnComparison | Sort-Object { -$_.Mbps }

$rank = 0
foreach ($vpn in $vpnComparison) {
    $rank++
    $isUs = $vpn.Name -eq "NovaVPN"

    $nameStr  = $vpn.Name.PadRight(18)
    $mbpsStr  = ("$($vpn.Mbps) Мбит/с").PadRight(14)
    $rttStr   = ("RTT ~$($vpn.RttUs)мкс").PadRight(16)

    # Бар для throughput (1 блок на 100 Мбит)
    $barLen = [math]::Min([math]::Round($vpn.Mbps / 100), 10)
    if ($barLen -lt 1) { $barLen = 1 }
    $bar = ([char]0x2588).ToString() * $barLen + ([char]0x2591).ToString() * (10 - $barLen)

    if ($isUs) {
        Write-Host -NoNewline ("  {0}. " -f $rank) -ForegroundColor Green
        Write-Host -NoNewline ">> $nameStr" -ForegroundColor Green
        Write-Host -NoNewline "$mbpsStr" -ForegroundColor Green
        Write-Host -NoNewline "$rttStr" -ForegroundColor Green
        Write-Host -NoNewline "$bar " -ForegroundColor Green
        Write-Host "<< $($vpn.Note)" -ForegroundColor Green
    } else {
        Write-Host -NoNewline ("  {0}. " -f $rank) -ForegroundColor DarkGray
        Write-Host -NoNewline "   $nameStr" -ForegroundColor White
        Write-Host -NoNewline "$mbpsStr" -ForegroundColor DarkGray
        Write-Host -NoNewline "$rttStr" -ForegroundColor DarkGray
        Write-Host -NoNewline "$bar " -ForegroundColor DarkGray
        Write-Host "   $($vpn.Note)" -ForegroundColor DarkGray
    }
}

# ═══════════════════════════════════════════════════════════
#  8. Итоговая оценка
# ═══════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                           ИТОГОВАЯ ОЦЕНКА NovaVPN                                ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Оценки по каждому параметру
$grades = @()

if ($bestThroughput -gt 0) {
    $tR = Get-ThroughputRating $bestThroughput
    Write-Host -NoNewline "    Пропускная способность:  " -ForegroundColor White
    Write-Host -NoNewline ("{0:F0} Мбит/с" -f $bestThroughput).PadRight(20) -ForegroundColor White
    Write-Host -NoNewline "$($tR.Bar)  " -ForegroundColor $tR.Color
    Write-Host "$($tR.Grade)" -ForegroundColor $tR.Color
    $grades += $tR.Grade
}

if ($bestRttP50us -gt 0) {
    $rR = Get-RttRating $bestRttP50us
    $rttLabel = if ($bestRttP50us -lt 1000) { "{0:F0} мкс" -f $bestRttP50us } else { "{0:F1} мс" -f ($bestRttP50us / 1000) }
    Write-Host -NoNewline "    Задержка (RTT p50):      " -ForegroundColor White
    Write-Host -NoNewline $rttLabel.PadRight(20) -ForegroundColor White
    Write-Host -NoNewline "$($rR.Bar)  " -ForegroundColor $rR.Color
    Write-Host "$($rR.Grade)" -ForegroundColor $rR.Color
    $grades += $rR.Grade
}

if ($bestHsMs -gt 0) {
    $hR = Get-HandshakeRating $bestHsMs
    $hsLabel = if ($bestHsMs -lt 1000) { "{0:F0} мс" -f $bestHsMs } else { "{0:F2} с" -f ($bestHsMs / 1000) }
    Write-Host -NoNewline "    Handshake (1 клиент):    " -ForegroundColor White
    Write-Host -NoNewline $hsLabel.PadRight(20) -ForegroundColor White
    Write-Host -NoNewline "$($hR.Bar)  " -ForegroundColor $hR.Color
    Write-Host "$($hR.Grade)" -ForegroundColor $hR.Color
    $grades += $hR.Grade
}

$lR = Get-LossRating $worstLoss
Write-Host -NoNewline "    Потери пакетов (worst):  " -ForegroundColor White
Write-Host -NoNewline ("{0:F2}%" -f $worstLoss).PadRight(20) -ForegroundColor White
Write-Host -NoNewline "$($lR.Bar)  " -ForegroundColor $lR.Color
Write-Host "$($lR.Grade)" -ForegroundColor $lR.Color
$grades += $lR.Grade

if ($maxClients -gt 1) {
    $sR = Get-ScaleRating $maxClients $maxConnected
    Write-Host -NoNewline "    Масштабируемость:        " -ForegroundColor White
    Write-Host -NoNewline ("$maxConnected/$maxClients клиентов").PadRight(20) -ForegroundColor White
    Write-Host -NoNewline "$($sR.Bar)  " -ForegroundColor $sR.Color
    Write-Host "$($sR.Grade)" -ForegroundColor $sR.Color
    $grades += $sR.Grade
}

# Общая оценка — средневзвешенная с учётом бутылочного горлышка
$gradeValues = @{ "ОТЛИЧНО" = 4; "ХОРОШО" = 3; "НОРМ" = 2; "ПЛОХО" = 1 }
$reverseGrade = @{ 4 = "ОТЛИЧНО"; 3 = "ХОРОШО"; 2 = "НОРМ"; 1 = "ПЛОХО" }

$minVal = 4
$sumVal = 0
foreach ($g in $grades) {
    $v = $gradeValues[$g]
    $sumVal += $v
    if ($v -lt $minVal) { $minVal = $v }
}
$avgVal = [int][math]::Round($sumVal / [math]::Max($grades.Count, 1))
# Общая = среднее, но не выше минимального + 1 (бутылочное горлышко тянет вниз)
$overallVal = [int][math]::Min($avgVal, $minVal + 1)
$overallGrade = $reverseGrade[$overallVal]

if     ($overallGrade -eq "ОТЛИЧНО") { $overallColor = "Green" }
elseif ($overallGrade -eq "ХОРОШО")  { $overallColor = "DarkGreen" }
elseif ($overallGrade -eq "НОРМ")    { $overallColor = "Yellow" }
else                                  { $overallColor = "Red" }

Write-Host ""
Write-Host "    ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray

if     ($overallGrade -eq "ОТЛИЧНО") { $fullBars = 5 }
elseif ($overallGrade -eq "ХОРОШО")  { $fullBars = 4 }
elseif ($overallGrade -eq "НОРМ")    { $fullBars = 3 }
else                                  { $fullBars = 2 }
$overallBar = ([char]0x2588).ToString() * $fullBars + ([char]0x2591).ToString() * (5 - $fullBars)

Write-Host -NoNewline "    ОБЩАЯ ОЦЕНКА:                                 " -ForegroundColor White
Write-Host -NoNewline "$overallBar  " -ForegroundColor $overallColor
Write-Host "★ $overallGrade ★" -ForegroundColor $overallColor

# Комментарий
Write-Host ""
if ($overallGrade -eq "ОТЛИЧНО") {
    Write-Host "    Сервер работает на уровне лучших VPN решений!" -ForegroundColor Green
    Write-Host "    Throughput и задержка на уровне WireGuard/IPsec." -ForegroundColor Green
} elseif ($overallGrade -eq "ХОРОШО") {
    Write-Host "    Сервер показывает хороший результат, на уровне IPsec/OpenConnect." -ForegroundColor DarkGreen
    Write-Host "    С учётом stealth-маскировки (которой нет у конкурентов) — отличный результат." -ForegroundColor DarkGreen
} elseif ($overallGrade -eq "НОРМ") {
    Write-Host "    Сервер работает на уровне OpenVPN." -ForegroundColor Yellow
    Write-Host "    Есть потенциал для дальнейшей оптимизации." -ForegroundColor Yellow
} else {
    Write-Host "    Сервер требует оптимизации." -ForegroundColor Red
    Write-Host "    Проверьте ресурсы VPS (CPU, RAM, сеть)." -ForegroundColor Red
}

Write-Host ""
Write-Host "    Примечание: NovaVPN имеет уникальную QUIC stealth-обёртку для обхода DPI," -ForegroundColor DarkGray
Write-Host "    которой не обладает ни один из сравниваемых VPN. Это создаёт дополнительный" -ForegroundColor DarkGray
Write-Host "    overhead, но делает трафик неотличимым от QUIC/HTTP3 для систем фильтрации." -ForegroundColor DarkGray

# ═══════════════════════════════════════════════════════════
#  9. Сохранение сводного отчёта
# ═══════════════════════════════════════════════════════════

$summaryReport = @{
    timestamp              = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    server                 = "${sshHost}:${vpnPort}"
    duration_per_test      = $duration
    mode                   = if ($quick) { "quick" } else { "full" }
    best_throughput_mbps   = [math]::Round($bestThroughput, 1)
    best_rtt_p50_us        = [math]::Round($bestRttP50us)
    best_handshake_ms      = [math]::Round($bestHsMs)
    worst_loss_pct         = [math]::Round($worstLoss, 2)
    max_clients_tested     = $maxClients
    max_clients_connected  = $maxConnected
    overall_grade          = $overallGrade
    tests                  = @()
}

foreach ($result in $allResults) {
    $rep = $result.Report
    $summaryReport.tests += @{
        name               = $result.Name
        mode               = $result.Mode
        clients            = $result.Clients
        clients_connected  = $result.Clients - $rep.handshake_errors
        throughput_mbps    = [math]::Round($rep.mbits_per_sec, 1)
        rtt_p50_ns         = if ($rep.rtt) { $rep.rtt.p50_ns } else { 0 }
        rtt_p95_ns         = if ($rep.rtt) { $rep.rtt.p95_ns } else { 0 }
        handshake_avg_ns   = if ($rep.handshake) { $rep.handshake.avg_ns } else { 0 }
        packet_loss_pct    = $rep.packet_loss_percent
        packets_per_sec    = [math]::Round($rep.packets_per_sec, 1)
    }
}

$localJsonPath = Join-Path $projectDir "bench-summary.json"
$summaryReport | ConvertTo-Json -Depth 5 | Set-Content -Path $localJsonPath -Encoding UTF8
Write-Host ""
Write-Host "[OK] Сводный JSON-отчёт: $localJsonPath" -ForegroundColor Green

# ═══════════════════════════════════════════════════════════
# 10. Очистка
# ═══════════════════════════════════════════════════════════

Remove-SSHSession -SSHSession $session | Out-Null
Remove-Item $binaryPath -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[ГОТОВО] Полный бенчмарк завершён" -ForegroundColor Green
Write-Host ""
