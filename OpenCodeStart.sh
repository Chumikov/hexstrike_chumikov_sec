#!/bin/bash
VENV_PYTHON="/usr/share/hexstrike-ai/venv/bin/python3"
GUNICORN_WRAPPER="/usr/share/hexstrike-ai/gunicorn.sh"
HEALTH_URL="http://127.0.0.1:8888/health"

if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "venv не найден. Запустите: sudo bash migrate_to_gunicorn.sh" >&2
    exit 1
fi

check_server() { curl -s -f "$HEALTH_URL" > /dev/null 2>&1; }

if ! check_server; then
    systemctl start hexstrike 2>/dev/null || \
    "$GUNICORN_WRAPPER" --bind 127.0.0.1:8888 --workers 2 \
        --chdir /usr/share/hexstrike-ai --daemon hexstrike_server:app
    sleep 2
fi

exec "$VENV_PYTHON" /usr/share/hexstrike-ai/hexstrike_mcp.py
