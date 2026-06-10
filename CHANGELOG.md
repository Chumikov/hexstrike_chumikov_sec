# Changelog

Все заметные изменения проекта HexStrike AI (Chumikov Sec Fork) документируются здесь.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

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
