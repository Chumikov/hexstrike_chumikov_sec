#!/bin/bash
# Запуск HexStrike MCP-клиента для OpenCode в режиме STDIO (по умолчанию).
# Этот скрипт — точка входа stdio: OpenCode порождает процесс и общается по stdin/stdout.
# Для streamable/sse-транспорта НЕ используйте этот скрипт — вместо него работает
# сервис hexstrike-mcp (deploy.sh), а OpenCode переключается на remote + url.
VENV_PYTHON="/usr/share/hexstrike-ai/venv/bin/python3"
GUNICORN_WRAPPER="/usr/share/hexstrike-ai/gunicorn.sh"
HEALTH_URL="http://127.0.0.1:8888/health"

if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "venv не найден. Запустите: sudo bash deploy.sh" >&2
    exit 1
fi

check_server() { curl -s -f "$HEALTH_URL" > /dev/null 2>&1; }

if ! check_server; then
    systemctl start hexstrike 2>/dev/null || \
    "$GUNICORN_WRAPPER" --bind 127.0.0.1:8888 --workers 2 \
        --chdir /usr/share/hexstrike-ai --daemon hexstrike_server:app
    sleep 2
fi

# Принудительно stdio для этой точки входа (F2, v6.3.0): даже если в окружении
# задан MCP_TRANSPORT=streamable/sse, stdio-лаунчер должен остаться stdio.
export MCP_TRANSPORT=stdio
exec "$VENV_PYTHON" /usr/share/hexstrike-ai/hexstrike_mcp.py
