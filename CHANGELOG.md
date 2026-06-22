# Changelog

Все заметные изменения проекта HexStrike AI (Chumikov Sec Fork) документируются здесь.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [6.4.0] — 2026-06-22

### Добавлено

- **Слой guardrails (G1–G6):** новый пакет `hexstrike_guardrails/` с пятью самостоятельными компонентами и Flask-интеграцией
  - **G1 `ScopeValidator`:** CIDR (IPv4/IPv6), wildcard, regex, hostname — контроль области тестирования на сессию. Вызов вне scope блокируется до выполнения. Корректная нормализация IPv6 literals (`[::1]:8080`) и trailing dots через `urllib.parse.urlsplit`. ReDoS-защита (cap regex length 256, compiled-once cache)
  - **G2 `Tier` + `TOOL_TIERS` + `classify_tool()`:** классификация всех 144 инструментов из `/health` + 25 MCP-инструментов (64 SAFE / 59 INTRUSIVE / 21 DESTRUCTIVE) + parameter-aware overrides (`nmap+aggressive` → DESTRUCTIVE, `execute_command`/`create_file` всегда DESTRUCTIVE) + token-based fallback для неизвестных
  - **G3 `TargetRateLimiter`:** per-target concurrency cap (Semaphore, default 5) + sliding-window rps (default 10), `acquire(timeout)` / `try_acquire` / `cleanup_stale(ttl)` для предотвращения утечки памяти
  - **G4 `KillSwitch`:** аварийная остановка всех процессов сессии или глобально (kill-all); race-free (lock held entire engage sequence, AUDIT fix); SIGTERM → SIGKILL эскалация с `kill_grace_sec`; глобальный флаг персистится в `metadata` для видимости из других Gunicorn-воркеров
  - **G5 `AuditLogger`:** append-only журнал в SQLite (`audit_log` table), параметризованный SQL, WAL mode, thread-safe (10 threads × 50 rows без потерь)
  - **G6 `register_guardrails(app)`:** Flask Blueprint с 9 эндпоинтами (`/api/guardrails/state|scope|validate|tiers|tier-summary|kill-all|reset|audit`, `/api/session/{id}/kill|audit`) + `wrap_executor()` декоратор для `execute_command_with_recovery` + error handler (`GuardrailsBlocked` → 403 / 429 / 503)
- **Персистентные пентест-сессии (G7):** новый модуль `pentest_session.py` с 11 эндпоинтами (`POST /api/session/create|close|finding|recon`, `GET /api/session/list|{id}|findings|surface|report`, `POST /api/session/{id}/finding/{fid}/confirm|fp`)
  - Адаптировано из `netcuter/Hexstrike-AI:pentest_session.py` с фиксами аудита: `uuid4().hex` ID (без коллизий), ownership-чек в confirm/fp (`WHERE id=? AND session_id=?`), markdown-escape тройных backticks, LEFT JOIN + GROUP BY вместо N+1, дедупликация через UNIQUE constraint
  - `QUICK_CVSS` mapping (28 записей: sqli=9.8, rce=9.8, xss_reflected=6.1, xss_stored=7.4, ssrf=8.8, idor=6.5, etc.)
  - Markdown-отчёт с executive summary, risk overview, attack surface, detailed findings, remediation priority, audit trail
- **SQLite-персистентность (общая):** `schemas/hexstrike_sessions.sql` — 6 таблиц (sessions, findings, recon_data, audit_log, kill_switch_events, metadata) + 13 индексов. Авто-создание `data/hexstrike_sessions.db` при первом запуске. WAL mode + foreign_keys. Данные переживают рестарт сервиса (в отличие от v6.3.0, где всё было in-memory)
- **UI в health-панели (G8):** расширение `templates/health_panel.html` тремя новыми секциями — GUARDRAILS (kill switch state, rate limits, scope pills, tier distribution), RECENT SESSIONS (severity breakdown), RECENT AUDIT (tier badges + status colors). Новая stat-card Kill Switch в верхней панели (IDLE/ENGAGED)
- **Тесты (T2):** 300 новых unit-тестов в 8 файлах — `test_guardrails_tiers.py` (85), `_scope.py` (48), `_rate_limiter.py` (23), `_killswitch.py` (14), `_audit.py` (15), `_integration.py` (28), `test_pentest_session.py` (57), `test_exploit_generators.py` (30, legacy добор AIExploitGenerator). Всего 115 → **415 тестов**. Покрытие новых модулей: `tiers.py` 96%, `scope.py` 96%, `rate_limiter.py` 94%, `audit.py` 85%, `state.py` 87%, `_db.py` 95%, `pentest_session.py` 70%
- **Env-флаги конфигурации:** `GUARDRAILS_DB`, `GUARDRAILS_MAX_CONCURRENT`, `GUARDRAILS_MAX_RPS`, `GUARDRAILS_RATE_TIMEOUT`, `GUARDRAILS_AUTOCONFIRM`
- `pytest.ini`: новый маркер `guardrails`, расширение `--cov` на `hexstrike_guardrails` и `pentest_session`
- `.gitignore`: `data/*.db`, `data/*.sqlite`, `data/*.db-journal/wal/shm`, `data/reports/`

### Изменено

- **`hexstrike_server.py`:**
  - `_register_optional_blueprints()` (module-level) — регистрирует guardrails + pentest_session на `app`. Безопасный fallback если пакет недоступен. Срабатывает и при `python hexstrike_server.py`, и при `gunicorn hexstrike_server:app`
  - `/health` HTML handler инжектит `guardrails` snapshot + `sessions` list в шаблон-контекст (lazy import; деградирует без guardrails)
  - `/health?json=1` отдаёт новый ключ `guardrails` со снапшотом состояния
- **CI (`.github/workflows/ci.yml`):** bump actions (CI-fix) — `checkout@v4→v6`, `setup-python@v5→v6` (Node.js 24 вместо 20, устраняет deprecated-warning в каждом прогоне с v6.3.0)
- **`tests/conftest.py`:** 7 новых fixtures для guardrails-тестов (`guardrails_db`, `fresh_state`, `audit_logger`, `kill_switch`, `session_manager`, `flask_guardrails_client`, `sample_scope_rules`)

### Безопасность

- Аудит `netcuter/Hexstrike-AI:guardrails.py` (514 строк) и `pentest_session.py` (907 строк): исправлено **5 HIGH**-дефектов (race в KillSwitch, time-based ID коллизии × 2, finding ownership bypass), **9 MEDIUM** (N+1, leak conn, MD injection, hardcoded mapping и др.), **7 LOW** (см. `docs/hexstrike_guardrails/AUDIT.md`, gitignored). Все SQL — параметризованные; все conn — context-managed

---

## [6.3.0] — 2026-06-20

### Добавлено

- **Транспорт MCP (F2):** `stdio` (по умолчанию), `sse`, `streamable-http` — переключение одной переменной `MCP_TRANSPORT`. Прямо лечит «обрывы OpenCode↔сервер» при длительных сканах
- Второй systemd-юнит `hexstrike-mcp.service` (порт 9010) для streamable/sse-режима; выключен по умолчанию
- CLI-флаги MCP: `--transport`, `--host`, `--port`; env: `MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT`
- **Оптимизатор контекста (F4):** `hexstrike_optimizer.py` — детерминированная постобработка вывода (strip ANSI, схлопывание прогресс-баров, дедупликация, трюнкация head+tail). Экономия токенов/ускорение цикла агент↔сервер. Вкл по умолчанию, env: `MCP_OPTIMIZER_ENABLED/MAX_CHARS/DEDUP/STRIP_ANSI`
- **Тестовая инфраструктура (T1):** `pytest`, `pytest-cov`, `pytest.ini`, `tests/` (115 unit-тестов), CI на GitHub Actions (Python 3.13). Покрытие: mcp.py 34%, server.py 14%
- **Синхронизация с upstream (F1):** `scripts/sync-upstream.sh` — maintenance-мерж `0x4m4/hexstrike-ai` с авто-защитой нашего набора файлов
- `requirements-dev.txt` для dev/test-зависимостей

### Изменено

- **Описания параметров инструментов (F3):** все 25 MCP-инструментов (102 параметра) переведены на `Annotated[type, Field(description=...)]` — описания теперь доходят до агента (FastMCP не парсит docstring `Args:`)
- `requirements.txt`: добавлен `uvicorn` (рантайм SSE/streamable-http)
- `deploy.sh`: копирование `hexstrike_optimizer.py`; новый шаг создания `hexstrike-mcp.service`; 11→12 шагов
- `OpenCodeStart.sh`: явная фиксация `MCP_TRANSPORT=stdio`; исправлена устаревшая ссылка на `deploy.sh`
- Структура README обновлена под новые файлы

### Исправлено

- Health-check MCP-клиента запрашивал `/health` (HTML-панель) вместо `/health?json` → ложные «Failed to establish connection» + ~10с задержка старта. Исправлено в `_initialize_connection` и `check_health`
- Регрессионный тест `test_tool_schemas.py` фиксирует валидность всех `inputSchema` и наличие описаний

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
