#!/bin/bash
HEALTH_URL="http://127.0.0.1:8888/health"
check_server() { curl -s -f "$HEALTH_URL" > /dev/null 2>&1; }
if ! check_server; then
    systemctl start hexstrike 2>/dev/null || \
    /home/kali/.local/bin/gunicorn --bind 127.0.0.1:8888 --workers 2 \
        --chdir /usr/share/hexstrike-ai --daemon hexstrike_server:app
    sleep 2
fi
exec python3 /usr/share/hexstrike-ai/hexstrike_mcp.py
