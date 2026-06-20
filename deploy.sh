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
VENV_DIR="${HEXSTRIKE_DIR}/venv"

STEP=0
STEPS_TOTAL=12

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
echo -e "${RED}███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗${NC}"
echo -e "${RED}██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝${NC}"
echo -e "${RED}██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗${NC}"
echo -e "${RED}╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝${NC}"
echo ""
echo "  Деплой HexStrike AI"
echo ""

check_root

RUN_USER=$(detect_user)
RUN_GROUP="$RUN_USER"
info "Пользователь службы: ${RUN_USER}"

# ============================================================================

step "Проверка окружения"

if [[ ! -f "${HEXSTRIKE_DIR}/hexstrike_server.py" ]]; then
    fail "hexstrike_server.py не найден в ${HEXSTRIKE_DIR}. Установите hexstrike-ai: sudo apt install hexstrike-ai"
fi
ok "hexstrike_server.py найден"

if ! id "$RUN_USER" &>/dev/null; then
    fail "Пользователь ${RUN_USER} не существует"
fi
ok "Пользователь ${RUN_USER} существует"

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_OK=$(python3 -c "import sys; ok = sys.version_info >= (3, 10); print(ok)")
if [[ "$PYTHON_OK" != "True" ]]; then
    fail "Требуется Python >= 3.10, установлена ${PYTHON_VERSION}"
fi
ok "Python ${PYTHON_VERSION} (>= 3.10)"

if ! curl -sf --connect-timeout 5 --max-time 10 https://pypi.python.org/simple/ >/dev/null 2>&1; then
    warn "PyPI недоступен — pip install может не сработать"
    warn "Убедитесь, что есть доступ к интернету"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================================

step "Копирование файлов проекта"

cp "${SCRIPT_DIR}/hexstrike_server.py" "${HEXSTRIKE_DIR}/hexstrike_server.py"
ok "hexstrike_server.py скопирован"

cp "${SCRIPT_DIR}/hexstrike_mcp.py" "${HEXSTRIKE_DIR}/hexstrike_mcp.py"
ok "hexstrike_mcp.py скопирован"

if [[ -f "${SCRIPT_DIR}/hexstrike_optimizer.py" ]]; then
    cp "${SCRIPT_DIR}/hexstrike_optimizer.py" "${HEXSTRIKE_DIR}/hexstrike_optimizer.py"
    ok "hexstrike_optimizer.py скопирован"
else
    fail "hexstrike_optimizer.py не найден в ${SCRIPT_DIR} (нужен hexstrike_mcp.py)"
fi

if [[ -d "${SCRIPT_DIR}/templates" ]]; then
    mkdir -p "${HEXSTRIKE_DIR}/templates"
    cp -a "${SCRIPT_DIR}/templates/." "${HEXSTRIKE_DIR}/templates/"
    ok "templates/ скопирован"
else
    warn "Директория templates/ не найдена, пропускаем"
fi

if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
    cp "${SCRIPT_DIR}/VERSION" "${HEXSTRIKE_DIR}/VERSION"
    ok "VERSION скопирован ($(cat ${SCRIPT_DIR}/VERSION))"
else
    warn "Файл VERSION не найден, пропускаем"
fi

if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
    cp "${SCRIPT_DIR}/requirements.txt" "${HEXSTRIKE_DIR}/requirements.txt"
    ok "requirements.txt скопирован"
else
    fail "Файл requirements.txt не найден в ${SCRIPT_DIR}"
fi

cp "${SCRIPT_DIR}/OpenCodeStart.sh" "${HEXSTRIKE_DIR}/OpenCodeStart.sh"
chmod +x "${HEXSTRIKE_DIR}/OpenCodeStart.sh"
ok "OpenCodeStart.sh скопирован"

# ============================================================================

step "Создание виртуального окружения"

if [[ -d "${VENV_DIR}" ]]; then
    info "venv уже существует, пересоздаём для чистоты..."
    rm -rf "${VENV_DIR}"
fi

python3 -m venv --system-site-packages "${VENV_DIR}"
ok "venv создан в ${VENV_DIR}"

chown -R "${RUN_USER}:${RUN_GROUP}" "${VENV_DIR}"
ok "Владелец venv: ${RUN_USER}:${RUN_GROUP}"

VENV_PYTHON="${VENV_DIR}/bin/python3"
VENV_PIP="${VENV_DIR}/bin/pip"

if [[ ! -x "$VENV_PYTHON" ]]; then
    fail "python3 не найден в venv"
fi
ok "Python venv: ${VENV_PYTHON}"

SYSTEM_PKGS=$(${VENV_PIP} list --format=columns 2>/dev/null | wc -l)
info "Системных пакетов доступно через --system-site-packages"

# ============================================================================

step "Установка зависимостей"

info "Установка из requirements.txt..."
if ! ${VENV_PIP} install -r "${HEXSTRIKE_DIR}/requirements.txt" 2>&1; then
    fail "pip install завершился с ошибкой. Проверьте доступ к PyPI и совместимость пакетов."
fi
ok "Зависимости установлены"

INSTALLED_VERSION=$(${VENV_PIP} show flask 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "unknown")
info "flask: ${INSTALLED_VERSION}"
INSTALLED_VERSION=$(${VENV_PIP} show mcp 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "unknown")
info "mcp: ${INSTALLED_VERSION}"
INSTALLED_VERSION=$(${VENV_PIP} show gunicorn 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "unknown")
info "gunicorn: ${INSTALLED_VERSION}"

chown -R "${RUN_USER}:${RUN_GROUP}" "${VENV_DIR}"

# ============================================================================

step "Создание gunicorn wrapper"

GUNICORN_WRAPPER="${HEXSTRIKE_DIR}/gunicorn.sh"
cat > "$GUNICORN_WRAPPER" << WRAPPER
#!/bin/bash
exec ${VENV_DIR}/bin/python3 -m gunicorn "\$@"
WRAPPER
chmod +x "$GUNICORN_WRAPPER"
chown "${RUN_USER}:${RUN_GROUP}" "$GUNICORN_WRAPPER"
ok "gunicorn.sh создан: ${GUNICORN_WRAPPER}"
ok "Использует venv python: ${VENV_DIR}/bin/python3"

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

VENV_BIN="${VENV_DIR}/bin"
SYSTEMD_PATH="PATH=${VENV_BIN}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/home/${RUN_USER}/go/bin:/home/${RUN_USER}/.local/bin:/home/${RUN_USER}/.cargo/bin"

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
ExecStart=${GUNICORN_WRAPPER} --bind 127.0.0.1:${HEXSTRIKE_PORT} --workers ${WORKERS} --timeout ${TIMEOUT} --max-requests ${MAX_REQUESTS} hexstrike_server:app
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

HEALTH_JSON=$(curl -sf "http://127.0.0.1:${HEXSTRIKE_PORT}/health?json" 2>/dev/null || echo "{}")
STATUS_IN_JSON=$(echo "$HEALTH_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")

if [[ "$STATUS_IN_JSON" == "healthy" || "$STATUS_IN_JSON" == "ok" ]]; then
    ok "Health check: ${STATUS_IN_JSON}"
else
    warn "Health check вернул: ${STATUS_IN_JSON}"
fi

SERVER_VERSION=$(echo "$HEALTH_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','unknown'))" 2>/dev/null || echo "unknown")
ok "Версия сервера: ${SERVER_VERSION}"

TOOLS_AVAILABLE=$(echo "$HEALTH_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{d.get(\"total_tools_available\",0)}/{d.get(\"total_tools_count\",0)}')" 2>/dev/null || echo "unknown")
ok "Инструменты: ${TOOLS_AVAILABLE}"

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

VENV_PYTHON_VERSION=$(${VENV_PYTHON} --version 2>/dev/null || echo "unknown")
ok "venv Python: ${VENV_PYTHON_VERSION}"

VENV_FLASK=$(${VENV_PIP} show flask 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "unknown")
ok "venv flask: ${VENV_FLASK}"

# ============================================================================

step "Создание MCP systemd unit (опционально, streamable/sse)"

MCP_SERVICE_FILE="/etc/systemd/system/hexstrike-mcp.service"
MCP_PORT="${MCP_PORT:-9010}"
MCP_TRANSPORT_DEFAULT="${MCP_TRANSPORT:-streamable}"

cat > "$MCP_SERVICE_FILE" << EOF
[Unit]
Description=HexStrike AI MCP Server (streamable-http/sse transport)
After=network.target hexstrike.service
Requires=hexstrike.service

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
WorkingDirectory=${HEXSTRIKE_DIR}
Environment="${SYSTEMD_PATH}"
Environment="MCP_TRANSPORT=${MCP_TRANSPORT_DEFAULT}"
Environment="MCP_HOST=127.0.0.1"
Environment="MCP_PORT=${MCP_PORT}"
ExecStart=${VENV_PYTHON} ${HEXSTRIKE_DIR}/hexstrike_mcp.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

ok "Файл ${MCP_SERVICE_FILE} создан"
systemctl daemon-reload
ok "systemctl daemon-reload выполнен"

# НЕ включаем автоматически: по умолчанию используется stdio (OpenCodeStart.sh).
# Пользователь включает streamable/sse явно, когда хочет переключить транспорт.
if systemctl is-enabled hexstrike-mcp &>/dev/null; then
    ok "Сервис hexstrike-mcp уже включён"
else
    info "Сервис hexstrike-mcp НЕ включён (по умолчанию = stdio через OpenCodeStart.sh)"
    info "Для streamable/sse: sudo systemctl enable --now hexstrike-mcp"
    info "Затем переключите OpenCode на remote: url http://127.0.0.1:${MCP_PORT}/mcp"
fi

# ============================================================================

step "Итог"

echo ""
echo -e "${GREEN}╭─────────────────────────────────────────────────────────────────╮${NC}"
echo -e "${GREEN}│  Деплой HexStrike AI завершён успешно                          │${NC}"
echo -e "${GREEN}├─────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${GREEN}│${NC}  Gunicorn:    ${GUNICORN_WRAPPER}"
echo -e "${GREEN}│${NC}  venv:        ${VENV_DIR}"
echo -e "${GREEN}│${NC}  Порт:        127.0.0.1:${HEXSTRIKE_PORT}"
echo -e "${GREEN}│${NC}  Workers:     ${WORKERS}"
echo -e "${GREEN}│${NC}  Timeout:     ${TIMEOUT}s"
echo -e "${GREEN}│${NC}  Max Requests:${MAX_REQUESTS}"
echo -e "${GREEN}│${NC}  Сервис:      ${SERVICE_FILE}"
echo -e "${GREEN}│${NC}  Автозапуск:  ${BOOT_ENABLED}"
echo -e "${GREEN}╰─────────────────────────────────────────────────────────────────╯${NC}"
echo ""
