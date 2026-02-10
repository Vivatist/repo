#!/bin/bash
# ═══════════════════════════════════════════
# NovaVPN — Скрипт добавления пользователя
# ═══════════════════════════════════════════
set -euo pipefail

SERVER_BIN="/usr/local/bin/novavpn-server"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Запустите от root: sudo $0${NC}"
    exit 1
fi

if [[ ! -f "$SERVER_BIN" ]]; then
    echo -e "${RED}NovaVPN не установлен. Запустите setup.sh${NC}"
    exit 1
fi

echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  NovaVPN — Добавление пользователя${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""

# Запрашиваем email
read -p "Email пользователя: " USER_EMAIL
if [[ -z "$USER_EMAIL" ]]; then
    echo -e "${RED}Email не может быть пустым${NC}"
    exit 1
fi

# Валидация email (базовая)
if [[ ! "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo -e "${RED}Некорректный формат email${NC}"
    exit 1
fi

# Запрашиваем пароль
read -sp "Пароль (мин. 8 символов): " USER_PASSWORD
echo ""

if [[ ${#USER_PASSWORD} -lt 8 ]]; then
    echo -e "${RED}Пароль должен быть не менее 8 символов${NC}"
    exit 1
fi

read -sp "Повторите пароль: " USER_PASSWORD_CONFIRM
echo ""

if [[ "$USER_PASSWORD" != "$USER_PASSWORD_CONFIRM" ]]; then
    echo -e "${RED}Пароли не совпадают${NC}"
    exit 1
fi

# Опционально: фиксированный IP
echo ""
read -p "Фиксированный VPN IP (Enter — автоматически): " FIXED_IP

# Собираем команду
CMD="$SERVER_BIN -adduser -email \"$USER_EMAIL\" -password \"$USER_PASSWORD\""
if [[ -n "$FIXED_IP" ]]; then
    CMD="$CMD -ip \"$FIXED_IP\""
fi

# Выполняем
eval $CMD

if [[ $? -eq 0 ]]; then
    # Читаем данные для клиента
    CONFIG_DIR="/etc/novavpn"
    PSK=$(grep "pre_shared_key:" "${CONFIG_DIR}/server.yaml" | awk '{print $2}' | tr -d '"')
    SERVER_PORT=$(grep "listen_port:" "${CONFIG_DIR}/server.yaml" | awk '{print $2}' | tr -d '"')
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "<YOUR_SERVER_IP>")

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Пользователь добавлен!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}Данные для клиента:${NC}"
    echo ""
    echo -e "  Сервер:   ${SERVER_IP}:${SERVER_PORT}"
    echo -e "  Email:    ${USER_EMAIL}"
    echo -e "  Пароль:   (задан при создании)"
    echo -e "  PSK:      ${PSK}"
    echo ""
    echo -e "  ${RED}ВАЖНО: Передайте PSK клиенту по безопасному каналу!${NC}"
    echo ""
    echo -e "  Перезапустите сервер для применения:"
    echo -e "  sudo systemctl restart novavpn"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
fi
