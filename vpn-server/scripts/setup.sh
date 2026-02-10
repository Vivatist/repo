#!/bin/bash
# ═══════════════════════════════════════════════════════════
# NovaVPN Server — Скрипт установки и настройки для Ubuntu 22
# ═══════════════════════════════════════════════════════════
set -euo pipefail

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Директории
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/novavpn"
LOG_DIR="/var/log/novavpn"
SERVICE_NAME="novavpn"

print_banner() {
    echo -e "${BLUE}"
    echo "═══════════════════════════════════════════"
    echo "  NovaVPN Server — Установка"
    echo "  Ubuntu 22.04+"
    echo "═══════════════════════════════════════════"
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Этот скрипт должен быть запущен от root${NC}"
        echo "Используйте: sudo $0"
        exit 1
    fi
}

check_os() {
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        echo -e "${YELLOW}ПРЕДУПРЕЖДЕНИЕ: Этот скрипт оптимизирован для Ubuntu 22.04+${NC}"
        echo -e "${YELLOW}Продолжаем, но могут быть проблемы...${NC}"
    fi
}

install_dependencies() {
    echo -e "${GREEN}[1/7] Устанавливаем зависимости...${NC}"
    apt-get update -qq
    apt-get install -y -qq iptables iproute2 curl > /dev/null 2>&1
    echo -e "  ${GREEN}✓ Зависимости установлены${NC}"
}

install_golang() {
    echo -e "${GREEN}[2/7] Проверяем Go...${NC}"
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}')
        echo -e "  ${GREEN}✓ Go уже установлен: ${GO_VERSION}${NC}"
        return
    fi
    
    echo -e "  Устанавливаем Go 1.21..."
    GO_TAR="go1.21.6.linux-amd64.tar.gz"
    curl -sL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm "/tmp/${GO_TAR}"
    
    # Добавляем в PATH
    export PATH=$PATH:/usr/local/go/bin
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    echo -e "  ${GREEN}✓ Go установлен: $(go version)${NC}"
}

build_server() {
    echo -e "${GREEN}[3/7] Собираем NovaVPN Server...${NC}"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    cd "$PROJECT_DIR"
    
    # Загружаем зависимости
    export PATH=$PATH:/usr/local/go/bin
    go mod tidy
    
    # Собираем
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags="-s -w" \
        -o "${INSTALL_DIR}/novavpn-server" \
        ./cmd/vpnserver/
    
    chmod +x "${INSTALL_DIR}/novavpn-server"
    
    echo -e "  ${GREEN}✓ Бинарник собран: ${INSTALL_DIR}/novavpn-server${NC}"
}

setup_config() {
    echo -e "${GREEN}[4/7] Настраиваем конфигурацию...${NC}"
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Генерируем PSK если конфигурация не существует
    if [[ ! -f "${CONFIG_DIR}/server.yaml" ]]; then
        PSK=$(${INSTALL_DIR}/novavpn-server -genkey 2>/dev/null | grep "PSK:" | awk '{print $2}')
        
        # Определяем внешний интерфейс
        EXT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
        
        cat > "${CONFIG_DIR}/server.yaml" << EOF
# ═══════════════════════════════════════════
# NovaVPN Server — Конфигурация
# ═══════════════════════════════════════════

# Адрес и порт для прослушивания
listen_addr: "0.0.0.0"
listen_port: 51820

# VPN подсеть
vpn_subnet: "10.8.0.0/24"
server_vpn_ip: "10.8.0.1"

# TUN-интерфейс
tun_name: "nova0"
mtu: 1400

# DNS для клиентов
dns:
  - "1.1.1.1"
  - "8.8.8.8"

# Pre-Shared Key (СЕКРЕТНЫЙ! Должен совпадать на клиентах)
pre_shared_key: "${PSK}"

# Файл пользователей (email + пароль)
users_file: "${CONFIG_DIR}/users.yaml"

# Лимиты
max_clients: 256
keepalive_interval: 25
session_timeout: 120

# NAT
enable_nat: true
external_interface: "${EXT_IFACE}"

# Логирование: debug, info, warn, error
log_level: "info"
EOF
        
        echo -e "  ${GREEN}✓ Конфигурация создана: ${CONFIG_DIR}/server.yaml${NC}"
        echo -e "  ${YELLOW}  PSK: ${PSK}${NC}"
        echo -e "  ${YELLOW}  СОХРАНИТЕ ЕГО! Он нужен для клиентов.${NC}"
    else
        echo -e "  ${YELLOW}  Конфигурация уже существует, пропускаем${NC}"
    fi
    
    # Создаём файл пользователей если не существует
    if [[ ! -f "${CONFIG_DIR}/users.yaml" ]]; then
        cat > "${CONFIG_DIR}/users.yaml" << EOF
# ═══════════════════════════════════════════
# NovaVPN — Пользователи
# ═══════════════════════════════════════════
# Добавление: novavpn-server -adduser -email user@example.com -password secret
#
users: []
EOF
        echo -e "  ${GREEN}✓ Файл пользователей создан: ${CONFIG_DIR}/users.yaml${NC}"
    fi
    
    # Устанавливаем права
    chmod 600 "${CONFIG_DIR}/server.yaml"
    chmod 600 "${CONFIG_DIR}/users.yaml"
}

setup_sysctl() {
    echo -e "${GREEN}[5/7] Настраиваем ядро...${NC}"
    
    # IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    
    # Persistent
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    # Оптимизации для VPN
    sysctl -w net.core.rmem_max=26214400 > /dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=26214400 > /dev/null 2>&1 || true
    sysctl -w net.core.rmem_default=1048576 > /dev/null 2>&1 || true
    sysctl -w net.core.wmem_default=1048576 > /dev/null 2>&1 || true
    
    echo -e "  ${GREEN}✓ IP forwarding включён${NC}"
    echo -e "  ${GREEN}✓ Буферы сокетов оптимизированы${NC}"
}

setup_firewall() {
    echo -e "${GREEN}[6/7] Настраиваем файрвол...${NC}"
    
    # Читаем порт из конфигурации или используем по умолчанию
    VPN_PORT=51820
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        PORT_FROM_CFG=$(grep "listen_port:" "${CONFIG_DIR}/server.yaml" | awk '{print $2}' | tr -d '"')
        if [[ -n "$PORT_FROM_CFG" ]]; then
            VPN_PORT=$PORT_FROM_CFG
        fi
    fi
    
    # Открываем UDP-порт
    if command -v ufw &> /dev/null; then
        ufw allow ${VPN_PORT}/udp > /dev/null 2>&1 || true
        echo -e "  ${GREEN}✓ UFW: открыт UDP порт ${VPN_PORT}${NC}"
    fi
    
    # iptables правило
    iptables -A INPUT -p udp --dport ${VPN_PORT} -j ACCEPT 2>/dev/null || true
    echo -e "  ${GREEN}✓ iptables: открыт UDP порт ${VPN_PORT}${NC}"
}

setup_systemd() {
    echo -e "${GREEN}[7/7] Настраиваем systemd сервис...${NC}"
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=NovaVPN Server
Documentation=https://github.com/novavpn/vpn-server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/novavpn-server -config ${CONFIG_DIR}/server.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5

# Безопасность
NoNewPrivileges=no
LimitNOFILE=65535
LimitNPROC=65535

# Логирование
StandardOutput=journal
StandardError=journal
SyslogIdentifier=novavpn

# Capabilities (минимальные права)
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME} > /dev/null 2>&1
    
    echo -e "  ${GREEN}✓ Systemd сервис создан и включён${NC}"
}

print_summary() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  NovaVPN Server установлен!${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Конфигурация:  ${CONFIG_DIR}/server.yaml"
    echo -e "  Пользователи:  ${CONFIG_DIR}/users.yaml"
    echo -e "  Бинарник:      ${INSTALL_DIR}/novavpn-server"
    echo -e "  Логи:          journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo -e "  ${YELLOW}Управление:${NC}"
    echo -e "  sudo systemctl start ${SERVICE_NAME}     # Запустить"
    echo -e "  sudo systemctl stop ${SERVICE_NAME}      # Остановить"
    echo -e "  sudo systemctl restart ${SERVICE_NAME}   # Перезапустить"
    echo -e "  sudo systemctl status ${SERVICE_NAME}    # Статус"
    echo ""
    echo -e "  ${YELLOW}Управление пользователями:${NC}"
    echo -e "  novavpn-server -adduser -email user@mail.com -password secret123"
    echo -e "  novavpn-server -listusers"
    echo -e "  novavpn-server -passwd   -email user@mail.com -password newpass"
    echo -e "  novavpn-server -disable  -email user@mail.com"
    echo -e "  novavpn-server -deluser  -email user@mail.com"
    echo ""
    echo -e "  ${YELLOW}Утилиты:${NC}"
    echo -e "  novavpn-server -genkey          # Новый PSK"
    echo -e "  novavpn-server -genconfig       # Пример конфигурации"
    echo ""
    echo -e "  ${YELLOW}Далее:${NC}"
    echo -e "  1. Отредактируйте ${CONFIG_DIR}/server.yaml"
    echo -e "  2. Добавьте пользователя:"
    echo -e "     novavpn-server -adduser -email user@example.com -password secret123"
    echo -e "  3. Запустите: sudo systemctl start ${SERVICE_NAME}"
    echo -e "  4. Клиенту дайте: сервер, PSK, email, пароль"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

# ===== MAIN =====
print_banner
check_root
check_os
install_dependencies
install_golang
build_server
setup_config
setup_sysctl
setup_firewall
setup_systemd
print_summary
