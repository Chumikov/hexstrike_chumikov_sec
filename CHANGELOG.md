# Changelog

Все заметные изменения проекта HexStrike AI (Chumikov Sec Fork) документируются здесь.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [6.4.5] — 2026-06-27

### Добавлено

- **MCP-консолидация по принципу «один глагол на класс задач» (C1+C2):** 6 новых MCP-инструментов-глаголов, заменяющих 14 специфичных тулов
  - `port_scan(target, mode, ports, tool)` ← `nmap_scan` + `nmap_advanced_scan` + `rustscan_fast_scan` (mode=fast/full/stealth/udp, auto→rustscan/nmap)
  - `subdomain_enum(domain, source, tool)` ← `amass_scan` + `subfinder_scan` (source=passive/active/all)
  - `http_probe(url, mode, depth, tool)` ← `httpx_probe` + `katana_crawl` (mode=probe/crawl/tech-detect)
  - `directory_brute(url, mode, wordlist, tool)` ← `gobuster_scan` + `ffuf_scan` + `dirsearch_scan` (mode=dir/vhost/fuzz)
  - `web_vuln_scan(target, profile, intensity, tool)` ← `nuclei_scan` + `nikto_scan` + покрывает `wpscan` (profile=generic/cms/legacy/wordpress)
  - `cloud_audit(scope, tool)` ← `prowler_scan` + `trivy_scan` + внутри диспетчерит на `kube-hunter`/`checkov` (scope=aws/k8s/docker/iac/all)
  - Каждый глагол — тонкая диспетчерская обёртка над **существующими** `/api/tools/*` роутами; бизнес-логика не дублируется
- **`metasploit_run` (C3) — закрытие destructive-gap'а:** новый first-class MCP-инструмент для Metasploit, обязательная маркировка `tier=DESTRUCTIVE` в `TOOL_TIERS`. Закрывает критический зазор, когда metasploit был доступен только через `execute_command` и обходил guardrails (v6.4.0). После инцидента с бронированием отелей 2026-06-23 — этический дифференциатор
- **`HEXSTRIKE_MCP_PROFILE` env var (C4) — server-side фильтрация инструментов:** 5 профилей (`minimal`/`recon`/`web`/`exploit`/`full`), работает в любом MCP-клиенте (OpenCode, Claude Desktop, Cursor, Cline). Не зависит от Anthropic quasi-static (который не работает в связке с GLM/OpenAI-compatible API). Дополнительно `HEXSTRIKE_MCP_ALIASES=0` прячет 14 deprecated имён
  - minimal=4 тула (~1 300 токенов), recon=7 (~2 400), web=9 (~3 100), exploit=13 (~3 900), full+aliases=32 (по умолчанию, обратная совместимость)
- **Принцип 6 в `Develop_Plan.md`:** «MCP-экономика: один глагол на класс задач» — зафиксирована методология

### Изменено

- **Расширение `hexstrike_guardrails/tiers.py`:** новые глаголы классифицированы — `subdomain_enum`/`http_probe`/`cloud_audit` → SAFE; `port_scan`/`directory_brute`/`web_vuln_scan` → INTRUSIVE; `metasploit_run` → DESTRUCTIVE. `metasploit` уже был в destructive, добавлено MCP-имя `metasploit_run`
- **14 старых инструментов помечены `[DEPRECATED v6.4.5, use XXX. Removed in v6.5.0]`** в docstring'ах (C5). Регистрируются только в `full` профиле при `HEXSTRIKE_MCP_ALIASES=1` (default). Удаляются в первом PR v6.5.0
- **`hexstrike_mcp.py` (+~340 строк):** profile-mechanism в начале `setup_mcp_server` (`_reg`, `_reg_alias`, `_tool` helper), 7 новых глаголов, условная регистрация всех существующих тулов через `@_tool(name, alias=.../full_only=...)`

### Тесты

- **41 новый тест в `tests/unit/test_mcp_v645_consolidation.py`** (T-c): проверка профилей (4/7/9/13 тулов), deprecated docstrings (14 алиасов), диспетчеризация глаголов (port_scan→nmap-advanced/rustscan/masscan, directory_brute→ffuf, subdomain_enum→subfinder, web_vuln_scan→wpscan, cloud_audit→kube-hunter), tier-классификация новых глаголов, metasploit_run как DESTRUCTIVE
- **Обновлён `test_tool_schemas.py`:** count 25 → 32 (25 legacy + 7 new verbs), добавлен `test_v645_new_verbs_present`
- **Всего: 415 → 456 тестов, все зелёные.** Регрессий v6.3.0/v6.4.0 нет

### Совместимость

- **100% backward compat:** default `HEXSTRIKE_MCP_PROFILE=full + HEXSTRIKE_MCP_ALIASES=1` сохраняет все 25 существующих имён + добавляет 7 новых = 32 инструмента. Существующие AGENTS.md, сохранённые диалоги, кастомные промпты работают без изменений
- **Token savings opt-in:** `HEXSTRIKE_MCP_PROFILE=recon` снижает нагрузку системного промпта на ~59% (5 832 → ~2 400 токенов на каждом ходе диалога)

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
