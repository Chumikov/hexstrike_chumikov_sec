# AGENTS.md — HexStrike AI v6.2.0 (Chumikov Sec Fork)

## О проекте

Форк HexStrike AI 6.0 с исправлениями и улучшениями для стабильной работы с OpenCode. Пентест-фреймворк для Kali Linux, интегрирующий 150+ security-инструментов через REST API + MCP.

## Структура

| Файл | Назначение |
|---|---|
| `VERSION` | Единый source of truth для версии проекта (SemVer) |
| `CHANGELOG.md` | История релизов |
| `requirements.txt` | Зависимости Python с фиксированными версиями |
| `hexstrike_server.py` (17k строк) | Flask REST API сервер — 156+ маршрутов, обёртки над security-инструментами |
| `hexstrike_mcp.py` (1.3k строк) | MCP-клиент на FastMCP — мост между AI-агентами и сервером |
| `migrate_to_gunicorn.sh` | Миграция на Gunicorn + venv + генерация systemd unit |
| `OpenCodeStart.sh` | Автозапуск сервера + MCP-клиента для OpenCode |
| `templates/health_panel.html` | Шаблон HTML-панели мониторинга |
| `README.md` | Документация (русский) |

## Архитектура

```
AI Agent (OpenCode) → MCP (stdio) → hexstrike_mcp.py → HTTP (localhost:8888) → hexstrike_server.py → subprocess → security tools
```

### Деплой-архитектура

```
/usr/share/hexstrike-ai/
├── venv/                    ← Python venv (--system-site-packages)
│   └── bin/
│       ├── python3          ← venv Python
│       ├── pip              ← pip для обновления зависимостей
│       └── gunicorn         ← gunicorn 26.0.0 [fast]
├── gunicorn.sh              ← wrapper: exec venv/bin/python3 -m gunicorn
├── hexstrike_server.py      ← читает VERSION, рендерит templates/
├── hexstrike_mcp.py         ← читает VERSION
├── templates/
│   └── health_panel.html
├── VERSION
├── requirements.txt
└── OpenCodeStart.sh         ← запускает MCP через venv python
```

## Технологии

- **Язык**: Python 3.10+, Bash
- **Сервер**: Flask + Gunicorn 26.0.0 [fast] (production)
- **MCP**: FastMCP 1.27.2, aiohttp 3.14.1 (async), requests 2.34.2 (sync fallback)
- **Деплой**: systemd + venv, bound to 127.0.0.1:8888
- **Целевая ОС**: Kali Linux

## Правки и деплой

Все файлы проекта копируются в `/usr/share/hexstrike-ai/` скриптом `migrate_to_gunicorn.sh`. Зависимости управляются через venv (`requirements.txt`), системные пакеты (mitmproxy и его deps) доступны через `--system-site-packages`.

Миграция: `sudo bash migrate_to_gunicorn.sh`

Проверка: `systemctl status hexstrike && curl http://127.0.0.1:8888/health`

## Конвенции

- **Коммиты**: на русском языке, описательные
- **Документация**: русский язык
- **Код**: Python с type hints, dataclass, Enum
- **Shell**: `set -euo pipefail`
- **Секционные заголовки**: `# ============ ... ===========`
- **Линтинг/тесты**: отсутствуют
- **Зависимости**: `requirements.txt` (pip в venv) + системные пакеты (apt)

## Важные участки кода

- **Health-check и обнаружение инструментов**: `hexstrike_server.py:9105-9217` — использует `which <tool>` для проверки наличия бинарников
- **Маппинг инструментов → команды**: `hexstrike_server.py:3530-3704` (`CTFToolManager.tool_commands`)
- **Интеллектуальный выбор инструментов**: `hexstrike_server.py:615-843` (`IntelligentDecisionEngine`)
- **Fallback-цепочки**: `hexstrike_server.py:1906-2269`
- **PATH для systemd**: `migrate_to_gunicorn.sh` — включает venv/bin
- **Кэширование MCP**: `hexstrike_mcp.py` — LRU cache (500 entries, 600s TTL)
- **Rate limiter MCP**: `hexstrike_mcp.py` — token bucket (10 req/s, burst 20)
- **Чтение версии**: `get_version()` в `hexstrike_server.py` и `hexstrike_mcp.py` — читает файл `VERSION`

## Безопасность

- API-ключи: `HEXSTRIKE_API_KEY`, `HEXSTRIKE_REQUIRE_AUTH`
- Редакция credentials в логах (`redact_credentials()`)
- Защита от path traversal (CWE-22)
- Привязка к localhost (не 0.0.0.0)
