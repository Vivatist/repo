<#
.SYNOPSIS
    Деплой NovaVPN Server на удалённый Linux-сервер.

.DESCRIPTION
    Собирает бинарник, загружает на сервер по SSH/SFTP и настраивает systemd-сервис.
    Поддерживает первичную установку (чистый сервер) и обновление (замена + перезапуск).

    Конфигурация: deploy-config.json (рядом со скриптом).
    Зависимость: модуль Posh-SSH (устанавливается автоматически).

.EXAMPLE
    .\deploy.ps1
#>

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir

# ═══════════════════════════════════════════════
#  1. Загрузка и валидация конфигурации
# ═══════════════════════════════════════════════

$configPath = Join-Path $scriptDir "deploy-config.json"
if (-not (Test-Path $configPath)) {
    Write-Host "[ОШИБКА] Файл конфигурации не найден: $configPath" -ForegroundColor Red
    Write-Host "Заполните deploy-config.json перед запуском." -ForegroundColor Yellow
    exit 1
}

$cfg = Get-Content $configPath -Raw -Encoding UTF8 | ConvertFrom-Json

$errors = @()
if (-not $cfg.ssh_host)     { $errors += "ssh_host — не указан IP/hostname сервера" }
if (-not $cfg.ssh_password) { $errors += "ssh_password — не указан пароль SSH" }
if (-not $cfg.ssh_user)     { $errors += "ssh_user — не указан логин SSH" }

if ($errors.Count -gt 0) {
    Write-Host "[ОШИБКА] Некорректная конфигурация ($configPath):" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

$sshHost      = $cfg.ssh_host
$sshPort      = if ($cfg.ssh_port)           { [int]$cfg.ssh_port }           else { 22 }
$sshUser      = $cfg.ssh_user
$sshPass      = $cfg.ssh_password
$vpnPort      = if ($cfg.vpn_port)           { [int]$cfg.vpn_port }           else { 443 }
$testEmail    = if ($cfg.test_user_email)     { $cfg.test_user_email }         else { "test@novavpn.app" }
$testPassword = if ($cfg.test_user_password)  { $cfg.test_user_password }      else { "NovaVPN2026!" }

Write-Host ""
Write-Host "  NovaVPN Server Deploy" -ForegroundColor Cyan
Write-Host "  =====================" -ForegroundColor Cyan
Write-Host "  Сервер:    $sshUser@${sshHost}:$sshPort"
Write-Host "  VPN порт:  $vpnPort (UDP)"
Write-Host "  Тест.юзер: $testEmail"
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
#  3. Сборка бинарника (Linux amd64)
# ═══════════════════════════════════════════════

Write-Host "[BUILD] Сборка novavpn-server (linux/amd64)..." -ForegroundColor Cyan

$binaryPath = Join-Path $scriptDir "novavpn-server"

Push-Location $projectDir
try {
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"

    $buildOutput = & go build -ldflags="-s -w" -o $binaryPath ./cmd/vpnserver/ 2>&1
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

$binarySize = [math]::Round((Get-Item $binaryPath).Length / 1MB, 1)
Write-Host "[BUILD] Готово ($binarySize MB)" -ForegroundColor Green

# ═══════════════════════════════════════════════
#  4. Генерация скрипта установки
# ═══════════════════════════════════════════════

$setupScript = @'
#!/bin/bash
set -e

VPN_PORT=__VPN_PORT__
TEST_EMAIL="__TEST_EMAIL__"
TEST_PASSWORD="__TEST_PASSWORD__"

BINARY="/usr/local/bin/novavpn-server"
CONFIG_DIR="/etc/novavpn"
CONFIG="$CONFIG_DIR/server.yaml"
SERVICE="novavpn"

echo ""
echo "=== NovaVPN Server Setup ==="
echo ""

# --- Определяем режим ---
IS_UPGRADE=false
if [ -f "$CONFIG" ]; then
    IS_UPGRADE=true
fi

# --- Останавливаем сервис (если запущен) ---
systemctl stop $SERVICE 2>/dev/null || true
sleep 1

# --- Устанавливаем бинарник ---
cp /tmp/novavpn-server $BINARY
chmod +x $BINARY
rm -f /tmp/novavpn-server
echo "[OK] Бинарник установлен: $BINARY"

if [ "$IS_UPGRADE" = true ]; then
    echo "[UPGRADE] Конфигурация сохранена, перезапуск..."
    systemctl start $SERVICE
    sleep 2
    if systemctl is-active --quiet $SERVICE; then
        echo "[OK] Сервис перезапущен"
        systemctl status $SERVICE --no-pager -l 2>/dev/null || true
    else
        echo "[FAIL] Сервис не запустился"
        journalctl -u $SERVICE --no-pager -n 15
        exit 1
    fi
    echo ""
    echo "DEPLOY_RESULT:UPGRADE_OK"
    exit 0
fi

# ═══ Первичная установка ═══
echo "[INSTALL] Первичная установка..."

mkdir -p $CONFIG_DIR

# --- Генерируем PSK ---
PSK=$(openssl rand -hex 32)

# --- Определяем внешний интерфейс ---
EXT_IF=$(ip route | grep default | awk '{print $5}' | head -1)
[ -z "$EXT_IF" ] && EXT_IF="eth0"
echo "[OK] Внешний интерфейс: $EXT_IF"

# --- Создаём конфиг сервера ---
cat > $CONFIG << CFGEND
listen_addr: "0.0.0.0"
listen_port: $VPN_PORT
vpn_subnet: "10.8.0.0/24"
server_vpn_ip: "10.8.0.1"
mtu: 1400
tun_name: "nova0"
enable_nat: true
external_interface: "$EXT_IF"
pre_shared_key: "$PSK"
users_file: "$CONFIG_DIR/users.yaml"
max_clients: 256
session_timeout: 120
keepalive_interval: 25
log_level: "info"
dns:
  - "1.1.1.1"
  - "8.8.8.8"
CFGEND
chmod 600 $CONFIG
echo "[OK] Конфигурация: $CONFIG"

# --- IP forwarding ---
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-novavpn.conf
echo "[OK] IP forwarding включён"

# --- Firewall ---
if command -v ufw &>/dev/null; then
    ufw allow $VPN_PORT/udp >/dev/null 2>&1 || true
    echo "[OK] UFW: порт $VPN_PORT/udp открыт"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --add-port=$VPN_PORT/udp --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "[OK] firewalld: порт $VPN_PORT/udp открыт"
fi
iptables -C INPUT -p udp --dport $VPN_PORT -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT 2>/dev/null || true

# --- Systemd сервис ---
cat > /etc/systemd/system/novavpn.service << 'UNITEND'
[Unit]
Description=NovaVPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/novavpn-server -config /etc/novavpn/server.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNITEND

systemctl daemon-reload
systemctl enable $SERVICE >/dev/null 2>&1
echo "[OK] Systemd сервис создан и включён"

# --- Тестовый пользователь (ДО запуска, чтобы сервер загрузил его при старте) ---
$BINARY -config $CONFIG -adduser -email "$TEST_EMAIL" -password "$TEST_PASSWORD" 2>&1 || true
echo "[OK] Тестовый пользователь: $TEST_EMAIL"

# --- Запуск ---
systemctl start $SERVICE
sleep 2

# --- Проверка ---
if systemctl is-active --quiet $SERVICE; then
    echo "[OK] Сервис запущен"
    systemctl status $SERVICE --no-pager -l 2>/dev/null || true
else
    echo "[FAIL] Сервис не запустился"
    journalctl -u $SERVICE --no-pager -n 15
    exit 1
fi

echo ""
echo "DEPLOY_PSK:$PSK"
echo "DEPLOY_RESULT:INSTALL_OK"
'@

# Подставляем параметры
$setupScript = $setupScript -replace '__VPN_PORT__',      $vpnPort
$setupScript = $setupScript -replace '__TEST_EMAIL__',     $testEmail
$setupScript = $setupScript -replace '__TEST_PASSWORD__',  $testPassword

# Сохраняем с LF-окончаниями строк
$setupScriptPath = Join-Path $env:TEMP "novavpn-setup.sh"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($setupScriptPath, $setupScript.Replace("`r`n", "`n"), $utf8NoBom)

# ═══════════════════════════════════════════════
#  5. Подключение к серверу
# ═══════════════════════════════════════════════

Write-Host "[SSH] Подключение к ${sshHost}:${sshPort}..." -ForegroundColor Cyan

$secPass = ConvertTo-SecureString $sshPass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($sshUser, $secPass)

try {
    $sshSession = New-SSHSession -ComputerName $sshHost -Port $sshPort -Credential $cred -AcceptKey -Force
} catch {
    Write-Host "[ОШИБКА] Не удалось подключиться по SSH: $_" -ForegroundColor Red
    Remove-Item $binaryPath       -ErrorAction SilentlyContinue
    Remove-Item $setupScriptPath  -ErrorAction SilentlyContinue
    exit 1
}
$sessionId = $sshSession.SessionId
Write-Host "[SSH] Подключено" -ForegroundColor Green

# ═══════════════════════════════════════════════
#  6. Проверка текущего состояния
# ═══════════════════════════════════════════════

$checkResult = Invoke-SSHCommand -SessionId $sessionId -Command "if [ -f /etc/novavpn/server.yaml ]; then echo 'installed'; else echo 'clean'; fi" -TimeOut 10
$serverState = ($checkResult.Output -join "").Trim()

if ($serverState -eq "installed") {
    # Получаем статус сервиса
    $statusResult = Invoke-SSHCommand -SessionId $sessionId -Command "systemctl is-active novavpn 2>/dev/null || echo 'stopped'" -TimeOut 10
    $serviceStatus = ($statusResult.Output -join "").Trim()

    Write-Host ""
    Write-Host "[!] Обнаружена существующая установка NovaVPN" -ForegroundColor Yellow
    Write-Host "    Статус сервиса: $serviceStatus" -ForegroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "    Заменить бинарник и перезапустить? (y/N)"
    if ($confirm -notin @("y", "Y", "д", "Д")) {
        Write-Host "Отменено." -ForegroundColor Yellow
        Remove-SSHSession -SessionId $sessionId | Out-Null
        Remove-Item $binaryPath       -ErrorAction SilentlyContinue
        Remove-Item $setupScriptPath  -ErrorAction SilentlyContinue
        exit 0
    }
}

# ═══════════════════════════════════════════════
#  7. Загрузка файлов на сервер (SFTP)
# ═══════════════════════════════════════════════

Write-Host "[UPLOAD] Загрузка файлов..." -ForegroundColor Cyan

try {
    $sftpSession = New-SFTPSession -ComputerName $sshHost -Port $sshPort -Credential $cred -AcceptKey -Force
    $sftpId = $sftpSession.SessionId

    Set-SFTPItem -SessionId $sftpId -Path $binaryPath      -Destination "/tmp/" -Force
    Set-SFTPItem -SessionId $sftpId -Path $setupScriptPath  -Destination "/tmp/" -Force

    Remove-SFTPSession -SessionId $sftpId | Out-Null
    Write-Host "[UPLOAD] Бинарник и скрипт загружены" -ForegroundColor Green
} catch {
    Write-Host "[ОШИБКА] Загрузка не удалась: $_" -ForegroundColor Red
    Remove-SSHSession -SessionId $sessionId | Out-Null
    Remove-Item $binaryPath       -ErrorAction SilentlyContinue
    Remove-Item $setupScriptPath  -ErrorAction SilentlyContinue
    exit 1
}

# ═══════════════════════════════════════════════
#  8. Выполнение установки на сервере
# ═══════════════════════════════════════════════

Write-Host "[DEPLOY] Выполняю установку на сервере..." -ForegroundColor Cyan

$deployResult = Invoke-SSHCommand -SessionId $sessionId `
    -Command "chmod +x /tmp/novavpn-setup.sh && bash /tmp/novavpn-setup.sh && rm -f /tmp/novavpn-setup.sh" `
    -TimeOut 120

# Выводим лог установки
$output = $deployResult.Output -join "`n"
$output -split "`n" | ForEach-Object {
    if ($_ -match "^\[OK\]")   { Write-Host "  $_" -ForegroundColor Green }
    elseif ($_ -match "^\[FAIL\]") { Write-Host "  $_" -ForegroundColor Red }
    elseif ($_ -match "^\[")   { Write-Host "  $_" -ForegroundColor Cyan }
    elseif ($_ -match "DEPLOY_") { <# скрываем служебные строки #> }
    elseif ($_.Trim())         { Write-Host "  $_" }
}

# Обработка stderr
if ($deployResult.Error) {
    $deployResult.Error -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
        Write-Host "  [stderr] $_" -ForegroundColor DarkYellow
    }
}

# ═══════════════════════════════════════════════
#  9. Результат
# ═══════════════════════════════════════════════

# Извлекаем результат
$psk = ""
if ($output -match "DEPLOY_PSK:(.+)") {
    $psk = $Matches[1].Trim()
}
$isSuccess = $output -match "DEPLOY_RESULT:(INSTALL_OK|UPGRADE_OK)"
$isInstall = $output -match "DEPLOY_RESULT:INSTALL_OK"

Write-Host ""

if ($isSuccess) {
    Write-Host "  ==============================" -ForegroundColor Green
    Write-Host "  ДЕПЛОЙ УСПЕШЕН" -ForegroundColor Green
    Write-Host "  ==============================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Адрес:  ${sshHost}:${vpnPort} (UDP)" -ForegroundColor White

    if ($isInstall -and $psk) {
        Write-Host ""
        Write-Host "  Юзер:   $testEmail" -ForegroundColor White
        Write-Host "  Пароль: $testPassword" -ForegroundColor White
        Write-Host ""
    }
} else {
    Write-Host "  ==============================" -ForegroundColor Red
    Write-Host "  ДЕПЛОЙ НЕ УДАЛСЯ" -ForegroundColor Red
    Write-Host "  ==============================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Проверьте логи: ssh ${sshUser}@${sshHost} journalctl -u novavpn -n 30" -ForegroundColor Yellow
}

# ═══ Cleanup ═══
Remove-SSHSession -SessionId $sessionId | Out-Null
Remove-Item $binaryPath       -ErrorAction SilentlyContinue
Remove-Item $setupScriptPath  -ErrorAction SilentlyContinue

Write-Host ""
