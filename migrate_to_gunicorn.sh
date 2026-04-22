#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

HEXSTRIKE_DIR="/usr/share/hexstrike-ai"
SERVICE_FILE="/etc/systemd/system/hexstrike.service"
HEXSTRIKE_PORT=8888
WORKERS=2
TIMEOUT=300
MAX_REQUESTS=1000

STEP=0
STEPS_TOTAL=8

step() {
    STEP=$((STEP + 1))
    echo ""
    echo -e "${CYAN}━━━ Шаг ${STEP}/${STEPS_TOTAL}: ${1} ━━━${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "Запусти скрипт от root: sudo bash $0"
    fi
}

detect_user() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "$SUDO_USER"
    else
        echo "root"
    fi
}

# ============================================================================

echo ""
echo -e "${RED}██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗${NC}"
echo -e "${RED}██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝${NC}"
echo -e "${RED}████████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗${NC}"
echo -e "${RED}██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝${NC}"
echo -e "${RED}██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗${NC}"
echo -e "${RED}╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝${NC}"
echo ""
echo "  Миграция HexStrike AI на Gunicorn"
echo ""

check_root

RUN_USER=$(detect_user)
RUN_GROUP="$RUN_USER"
info "Пользователь службы: ${RUN_USER}"

# ============================================================================

step "Проверка окружения"

if [[ ! -f "${HEXSTRIKE_DIR}/hexstrike_server.py" ]]; then
    fail "hexstrike_server.py не найден в ${HEXSTRIKE_DIR}"
fi
ok "hexstrike_server.py найден"

if ! id "$RUN_USER" &>/dev/null; then
    fail "Пользователь ${RUN_USER} не существует"
fi
ok "Пользователь ${RUN_USER} существует"

# ============================================================================

step "Установка Gunicorn"

GUNICORN_PATH=""
GUNICORN_WRAPPER=""

if command -v gunicorn &>/dev/null; then
    GUNICORN_PATH=$(command -v gunicorn)
    ok "Gunicorn уже установлен: ${GUNICORN_PATH}"
else
    info "Установка gunicorn..."
    apt-get install -y python3-gunicorn &>/dev/null || true

    for candidate in gunicorn gunicorn3; do
        if command -v "$candidate" &>/dev/null; then
            GUNICORN_PATH=$(command -v "$candidate")
            break
        fi
    done

    if [[ -z "$GUNICORN_PATH" ]]; then
        if python3 -c "import gunicorn" &>/dev/null; then
            GUNICORN_WRAPPER="${HEXSTRIKE_DIR}/gunicorn.sh"
            cat > "$GUNICORN_WRAPPER" << 'WRAPPER'
#!/bin/bash
exec python3 -m gunicorn "$@"
WRAPPER
            chmod +x "$GUNICORN_WRAPPER"
            GUNICORN_PATH="$GUNICORN_WRAPPER"
            ok "Gunicorn через python3 -m gunicorn (wrapper)"
        else
            info "Модуль не найден, ставим через pipx..."
            apt-get install -y pipx &>/dev/null || true
            if command -v pipx &>/dev/null; then
                pipx install gunicorn &>/dev/null
                GUNICORN_PATH=$(command -v gunicorn)
            fi
            if [[ -z "$GUNICORN_PATH" ]]; then
                fail "Не удалось установить gunicorn ни одним способом"
            fi
        fi
    fi
    ok "Gunicorn установлен: ${GUNICORN_PATH}"
fi

# ============================================================================

step "Освобождение порта ${HEXSTRIKE_PORT}"

PORT_PID=$(ss -tlnp 2>/dev/null | grep ":${HEXSTRIKE_PORT}" | grep -oP 'pid=\K[0-9]+' | head -1 || true)

if [[ -n "$PORT_PID" ]]; then
    warn "Порт ${HEXSTRIKE_PORT} занят процессом PID ${PORT_PID}"
    info "Останавливаем старый процесс..."
    kill "$PORT_PID" 2>/dev/null || true
    sleep 2

    PORT_PID_CHECK=$(ss -tlnp 2>/dev/null | grep ":${HEXSTRIKE_PORT}" | grep -oP 'pid=\K[0-9]+' | head -1 || true)
    if [[ -n "$PORT_PID_CHECK" ]]; then
        warn "Процесс не завершился корректно, принудительное завершение..."
        kill -9 "$PORT_PID_CHECK" 2>/dev/null || true
        sleep 1
    fi
    ok "Старый процесс остановлен"
else
    ok "Порт ${HEXSTRIKE_PORT} свободен"
fi

if systemctl is-active hexstrike &>/dev/null; then
    systemctl stop hexstrike
    ok "Остановлен существующий сервис hexstrike"
fi

# ============================================================================

step "Создание systemd unit"

USER_LOCAL_BIN=$(dirname "$GUNICORN_PATH")
SYSTEMD_PATH="PATH=${USER_LOCAL_BIN}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/home/${RUN_USER}/go/bin:/home/${RUN_USER}/.local/bin:/home/${RUN_USER}/.cargo/bin"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=HexStrike AI Server
After=network.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
WorkingDirectory=${HEXSTRIKE_DIR}
Environment="${SYSTEMD_PATH}"
ExecStart=${GUNICORN_PATH} --bind 127.0.0.1:${HEXSTRIKE_PORT} --workers ${WORKERS} --timeout ${TIMEOUT} --max-requests ${MAX_REQUESTS} hexstrike_server:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

ok "Файл ${SERVICE_FILE} создан"

# ============================================================================

step "Активация сервиса"

systemctl daemon-reload
ok "systemctl daemon-reload выполнен"

systemctl enable hexstrike
ok "Сервис добавлен в автозапуск"

systemctl start hexstrike
ok "Сервис запущен"

# ============================================================================

step "Ожидание запуска и проверка"

MAX_WAIT=30
WAITED=0
HEALTHY=false

while [[ $WAITED -lt $MAX_WAIT ]]; do
    if curl -sf "http://127.0.0.1:${HEXSTRIKE_PORT}/health" >/dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
    echo -ne "  Ожидание... ${WAITED}/${MAX_WAIT}s\r"
done

echo ""

if [[ "$HEALTHY" == true ]]; then
    ok "Health endpoint ответил за ${WAITED}s"
else
    warn "Health endpoint не ответил за ${MAX_WAIT}s"
    info "Диагностика:"
    systemctl status hexstrike --no-pager || true
    echo ""
    journalctl -u hexstrike --no-pager -n 20 || true
    fail "Сервис не поднялся. Проверь логи выше."
fi

# ============================================================================

step "Финальная проверка"

echo ""

SERVICE_STATUS=$(systemctl is-active hexstrike)
if [[ "$SERVICE_STATUS" == "active" ]]; then
    ok "Статус сервиса: active"
else
    fail "Статус сервиса: ${SERVICE_STATUS}"
fi

HEALTH_JSON=$(curl -sf "http://127.0.0.1:${HEXSTRIKE_PORT}/health" 2>/dev/null || echo "{}")
STATUS_IN_JSON=$(echo "$HEALTH_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")

if [[ "$STATUS_IN_JSON" == "healthy" || "$STATUS_IN_JSON" == "ok" ]]; then
    ok "Health check: ${STATUS_IN_JSON}"
else
    warn "Health check вернул: ${STATUS_IN_JSON}"
fi

GUNICORN_RUNNING=$(pgrep -c gunicorn 2>/dev/null || echo "0")
ok "Gunicorn worker'ов запущено: ${GUNICORN_RUNNING}"

PORT_LISTENING=$(ss -tlnp 2>/dev/null | grep ":${HEXSTRIKE_PORT}" | head -1 || true)
if [[ -n "$PORT_LISTENING" ]]; then
    ok "Порт ${HEXSTRIKE_PORT} слушает"
else
    warn "Порт ${HEXSTRIKE_PORT} не обнаружен"
fi

BOOT_ENABLED=$(systemctl is-enabled hexstrike 2>/dev/null || echo "unknown")
ok "Автозапуск: ${BOOT_ENABLED}"

# ============================================================================

step "Итог"

echo ""
echo -e "${GREEN}╭─────────────────────────────────────────────────────────────────╮${NC}"
echo -e "${GREEN}│  Миграция на Gunicorn завершена успешно                        │${NC}"
echo -e "${GREEN}├─────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${GREEN}│${NC}  Gunicorn:    ${GUNICORN_PATH}"
echo -e "${GREEN}│${NC}  Порт:        127.0.0.1:${HEXSTRIKE_PORT}"
echo -e "${GREEN}│${NC}  Workers:     ${WORKERS}"
echo -e "${GREEN}│${NC}  Timeout:     ${TIMEOUT}s"
echo -e "${GREEN}│${NC}  Max Requests:${MAX_REQUESTS}"
echo -e "${GREEN}│${NC}  Сервис:      ${SERVICE_FILE}"
echo -e "${GREEN}│${NC}  Автозапуск:  ${BOOT_ENABLED}"
echo -e "${GREEN}╰─────────────────────────────────────────────────────────────────╯${NC}"
echo ""
