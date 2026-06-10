# Changelog

Все заметные изменения проекта HexStrike AI (Chumikov Sec Fork) документируются здесь.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [6.2.0] — 2026-06-10

### Добавлено

- `requirements.txt` — управление зависимостями с фиксированными версиями
- Виртуальное окружение (venv) в `/usr/share/hexstrike-ai/venv/` с `--system-site-packages`
- `migrate_to_gunicorn.sh` автоматически создаёт venv и устанавливает зависимости через pip
- Gunicorn с extra `[fast]` — C-парсер `gunicorn_h1c` для ускорения HTTP
- Проверка Python >= 3.10 в скрипте миграции
- Вывод версии сервера и количества инструментов в финальной проверке

### Изменено

- **Обновлены зависимости:**
  - aiohttp 3.13.5 → 3.14.1 (30+ багфиксов, security: request smuggling, header injection)
  - beautifulsoup4 4.14.3 → 4.15.0 (исправление краша html.parser)
  - flask 3.1.2 → 3.1.3 (CVE-2026-27205, session access tracking)
  - gunicorn 25.3.0 → 26.0.0 (HTTP request smuggling protection, header hardening)
  - mcp 1.26.0 → 1.27.2 (security: command injection, auth session binding, memory leak fix)
  - psutil 7.1.0 → 7.2.2 (bugfixes, безопасные C-строковые функции)
  - requests 2.32.5 → 2.34.2 (CVE-2026-25645, inline type hints)
  - selenium 4.24.0 → 4.44.0 (CDP Chrome 126→148, BiDi API)
- `migrate_to_gunicorn.sh` — полная переработка: копирование файлов, создание venv, pip install, генерация gunicorn.sh
- `OpenCodeStart.sh` — использует venv python для MCP-клиента
- `gunicorn.sh` — использует venv python вместо системного

### Удалено

- Ручное копирование файлов — теперь `migrate_to_gunicorn.sh` копирует всё автоматически

## [6.1.1] — 2026-06-10

### Добавлено

- Версионность проекта: единый файл `VERSION` как source of truth
- `CHANGELOG.md` для истории релизов
- HTML-панель мониторинга `/health` (вместо голого JSON)
- JSON-ответ `/health` доступен через `?json` или `Accept: application/json`
- Информационные маркеры `*` для инструментов, не используемых HexStrike напрямую
- Директория `templates/` с `health_panel.html`

### Изменено

- `migrate_to_gunicorn.sh` теперь копирует `templates/` и `VERSION` при деплое
- `~/.cargo/bin` добавлен в PATH systemd unit для доступности rustscan

### Исправлено

- Стабилизация работы MCP-клиента с OpenCode
- Исправления ошибок в fallback-цепочках инструментов

## [6.0.0] — 2025-xx-xx

### Добавлено

- Форк HexStrike AI 6.0 (apt package `hexstrike-ai`)
- Миграция на Gunicorn + systemd (`migrate_to_gunicorn.sh`)
- MCP-клиент (`hexstrike_mcp.py`) — мост между AI-агентами и REST API
- 156+ маршрутов REST API для security-инструментов
- Кэширование MCP (LRU, 500 entries, 600s TTL)
- Rate limiter MCP (token bucket, 10 req/s, burst 20)
