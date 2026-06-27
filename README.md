# HexStrike AI — Chumikov Sec Fork

В своей статье https://habr.com/ru/articles/985450/ я рассмотрел интеграцию Hexstrike-AI и OpenCode в Kali Linux. С того времени вышло много обновлений OpenCode и всего пара патчей безопасности для HexStrike, а работа связки оставалась крайне нестабильной и местами медленной. Ждать обещанную 7-ю версию HexStrike (которая, судя по всему, не выйдет в open-source) я не стал — и начал развивать собственный форк.

Текущая версия: **v6.4.5 «Streamline»** (включает всё из не публиковавшейся ранее v6.4.0 «Guardrails»). Релиз добавляет слой guardrails (scope-валидация, классификация 144 инструментов по SAFE/INTRUSIVE/DESTRUCTIVE, per-target rate limiter, kill switch, audit log в SQLite, персистентные сессии с CVSS-скорингом и markdown-отчётами), а также консолидирует 14 близнецов-инструментов в 6 «глаголов» (`port_scan`, `subdomain_enum`, `http_probe`, `directory_brute`, `web_vuln_scan`, `cloud_audit`), добавляет `metasploit_run` под guardrails и env-профили `HEXSTRIKE_MCP_PROFILE` для экономии токенов. Всего **456 тестов** (+41 к v6.4.0).

Далее предполагается, что HexStrike и OpenCode у вас уже установлены (читайте мою статью).

---

# Содержание

1. [Установка и обновление](#установка-и-обновление)
2. [Структура проекта](#структура-проекта)
3. [Деплой](#деплой)
4. [Панель мониторинга](#панель-мониторинга)
5. [Настройка автозапуска и OpenCode](#настройка-автозапуска-и-opencode)
6. [Версионность](#версионность)
7. [Изменения в hexstrike_server.py](#изменения-в-hexstrike_serverpy)
8. [Изменения в hexstrike_mcp.py](#изменения-в-hexstrike_mcpy)
9. [Транспорт и оптимизация](#транспорт-и-оптимизация-v630)
10. [Тесты и разработка](#тесты-и-разработка)
11. [Guardrails и сессии (v6.4.0)](#guardrails-и-сессии-v640)
12. [MCP-консолидация и профили (v6.4.5)](#mcp-консолидация-и-профили-v645)
13. [Синхронизация с upstream](#синхронизация-с-upstream)

---

## Установка и обновление

### Требования

- Kali Linux
- Установленный пакет `hexstrike-ai` (`sudo apt install hexstrike-ai`)

### Первая установка

```bash
sudo apt install hexstrike-ai
git clone https://github.com/Chumikov/hexstrike_chumikov_sec.git
cd hexstrike_chumikov_sec
sudo bash deploy.sh
```

### Обновление до новой версии

```bash
cd hexstrike_chumikov_sec
git pull
sudo bash deploy.sh
```

### Проверка

```bash
systemctl status hexstrike
curl http://127.0.0.1:8888/health
```

---

## Структура проекта

| Файл | Назначение |
|---|---|
| `VERSION` | Версия проекта (SemVer), единый source of truth |
| `CHANGELOG.md` | История релизов |
| `hexstrike_server.py` | Flask REST API сервер — 156+ маршрутов, обёртки над security-инструментами |
| `hexstrike_mcp.py` | MCP-клиент на FastMCP — мост между AI-агентами и сервером |
| `hexstrike_optimizer.py` | Оптимизатор контекста/токенов (v6.3.0) |
| `hexstrike_guardrails/` | Слой безопасности: scope/tier/rate/kill/audit (v6.4.0, 9 модулей) |
| `pentest_session.py` | Персистентные пентест-сессии, CVSS, отчёты (v6.4.0) |
| `schemas/hexstrike_sessions.sql` | DDL: 6 таблиц SQLite для guardrails и сессий (v6.4.0) |
| `data/` | Runtime SQLite (`hexstrike_sessions.db`, gitignored) |
| `deploy.sh` | Полный деплой: venv, зависимости, systemd, проверка |
| `requirements.txt` | Зависимости Python с фиксированными версиями |
| `requirements-dev.txt` | Dev/test-зависимости (pytest, pytest-cov) |
| `OpenCodeStart.sh` | Автозапуск сервера + MCP-клиента для OpenCode |
| `templates/health_panel.html` | Шаблон HTML-панели мониторинга |
| `scripts/sync-upstream.sh` | Maintenance-синхронизация с upstream `0x4m4/hexstrike-ai` |
| `tests/` | Unit-тесты (pytest), 415 шт. |
| `.github/workflows/ci.yml` | CI: pytest на каждый push/PR |

---

## Деплой

### Архитектура сервера

По умолчанию, оригинальный HexStrike использует Flask, который использует встроенный development-сервер (`app.run()`) — он однопоточный, не имеет автоперезапуска, подвержен утечкам памяти, не переживает падения. Для фреймворка, который держит открытыми subprocess'ы Nmap/Nuclei/SQLMap по несколько минут, это неприемлемо.

### Преимущества Gunicorn перед Flask dev-сервером

- 2 worker-процесса вместо одного — параллельная обработка запросов, один долгий скан не блокирует API
- Автоперезапуск worker'ов после 1000 запросов (`--max-requests`) — защита от утечек памяти
- systemd-интеграция — автозапуск при загрузке, автоматический рестарт при падении (`Restart=on-failure`)
- Graceful reload — `kill -HUP` перезапускает worker'ов без даунтайма
- Таймаут 300с на уровне сервера — защита от зависших запросов

### Скрипт деплоя

`deploy.sh` выполняет все шаги автоматически (12 шагов):

1. Проверка окружения (root, наличие `hexstrike-ai`, Python >= 3.10, архитектуры)
2. Копирование файлов проекта: `hexstrike_server.py`, `hexstrike_mcp.py`, `hexstrike_optimizer.py`, `hexstrike_guardrails/`, `pentest_session.py`, `schemas/`, `templates/`, `VERSION`, `requirements.txt`; подготовка `data/` для SQLite
3. Создание venv с `--system-site-packages`
4. Установка зависимостей через pip
5. Генерация gunicorn wrapper (включая `~/.cargo/bin` для rustscan)
6. Освобождение порта 8888, если занят
7. Генерация systemd unit
8. `daemon-reload` + `enable` + `start` сервиса `hexstrike`
9. Ожидание health-check (до 30 сек)
10. Финальная проверка: статус, версия, инструменты, venv
11. Создание опционального MCP-юнита `hexstrike-mcp.service` (выключен по умолчанию — для streamable/sse-транспорта)
12. Итоговая сводка с путями и параметрами

При ошибке на любом этапе — выводит `systemctl status` и `journalctl` и останавливается.

#### Запуск

```bash
sudo bash deploy.sh
```

#### Ручная проверка

```bash
systemctl status hexstrike
curl http://127.0.0.1:8888/health
pgrep -c gunicorn
```

---

## Панель мониторинга

Health endpoint (`/health`) отдаёт визуальную HTML-панель вместо голого JSON.

- **`/health`** — HTML-панель с тёмным дизайном: прогресс-бары по категориям инструментов, сетка статуса (установлен/отсутствует), системные метрики (CPU, RAM, Disk, Network)
- **`/health?json`** или **`Accept: application/json`** — JSON-ответ для API (с v6.4.0 включает блок `guardrails` со снапшотом состояния)

Инструменты, которые отображаются только для информации о наличии в системе (не используются HexStrike напрямую), помечены значком `INFO`.

С v6.4.0 панель расширена тремя новыми секциями (видны только если установлен пакет `hexstrike_guardrails`):

- **GUARDRAILS** — статус kill switch (IDLE/ENGAGED), rate limits, scope pills, распределение инструментов по tier
- **RECENT SESSIONS** — последние 10 пентест-сессий с разбивкой находок по severity (🔴🟠🟡🔵)
- **RECENT AUDIT** — последние 15 событий guardrails с tier-бейджами и цветовой индикацией статуса

В верхней строке stat-cards добавились **Kill Switch** (мигает красным при тревоге) и **Blocks total** (сумма blocked_scope/tier/rate).

---

## Настройка автозапуска и OpenCode

### Конфигурация MCP OpenCode

Необходимо внести изменения в файл конфигурации MCP OpenCode, чтобы запуск использовал скрипт автозапуска:

Файл: `/home/kali/.opencode/opencode.jsonc`

Этот файл также может находиться в папке `/home/kali/.config/opencode`

```json
{
  "$schema": "https://opencode.ai/config.json",

  "experimental": {
    "mcp_timeout": 1200000
  },

  "mcp": {
    "hexstrike": {
      "type": "local",
      "command": ["bash", "/usr/share/hexstrike-ai/OpenCodeStart.sh"],
      "timeout": 1200000,
      "enabled": true
    }
  }
}
```

> Это конфигурация по умолчанию (stdio). Для streamable-http/sse-транспорта (стабильнее при долгих сканах) см. раздел [«Транспорт и оптимизация»](#транспорт-и-оптимизация-v630).

---

## Версионность

Начиная с v6.1.1, проект использует [SemVer](https://semver.org/lang/ru/):

- `VERSION` — единый файл с версией, читается сервером и MCP-клиентом
- `CHANGELOG.md` — история релизов
- Git-теги формата `vX.Y.Z` соответствуют релизам на GitHub

Текущую версию можно узнать через health endpoint:

```bash
curl -s http://127.0.0.1:8888/health?json | python3 -c "import sys,json; print(json.load(sys.stdin)['version'])"
```

---

## Изменения в hexstrike_server.py

Изменения развёртываются автоматически скриптом `deploy.sh`.

### Безопасность

- API аутентификация — поддержка ключей через `X-API-Key` и `Authorization: Bearer` заголовки
  - Переменные: `HEXSTRIKE_API_KEY`, `HEXSTRIKE_REQUIRE_AUTH`
- Редакция учётных данных — автоматическая маскировка паролей, токенов, API-ключей в логах (`redact_credentials()`)
- Защита от path traversal (CWE-22) — блокировка абсолютных путей, `../` последовательностей и null-байтов в `FileOperationsManager`
- Привязка к localhost — сервер слушает только `127.0.0.1` вместо `0.0.0.0`
- **Guardrails (v6.4.0)** — автоматическая регистрация `hexstrike_guardrails` и `pentest_session` через `_register_optional_blueprints()` на module level. Добавляет 20 новых эндпоинтов под `/api/guardrails/*` и `/api/session/*`; расширение `/health` HTML+JSON контекста (блок `guardrails`, секции GUARDRAILS/SESSIONS/AUDIT). Graceful fallback если пакет недоступен

### Кэширование

- Размер кэша увеличен с 1000 до **2000** записей
- TTL кэша увеличен с 3600 до **7200** секунд (2 часа)

---

## Изменения в hexstrike_mcp.py

Изменения развёртываются автоматически скриптом `deploy.sh`.

> Всего MCP-инструментов по умолчанию: **32** (25 legacy + 7 глаголов v6.4.5). Сокращается через `HEXSTRIKE_MCP_PROFILE` — см. [MCP-консолидация и профили (v6.4.5)](#mcp-консолидация-и-профили-v645). Изменения v6.3.0 (альтернативные транспорты, оптимизатор контекста, описания параметров, фикс health-check) — в разделе [«Транспорт и оптимизация»](#транспорт-и-оптимизация-v630).

### Асинхронные запросы

- `aiohttp` для асинхронных HTTP-запросов (`async_get()`, `async_post()`)
- Синхронный fallback через `requests` для совместимости
- Автоматическое управление жизненным циклом `aiohttp.ClientSession`

### Кэширование на MCP уровне

- `LRUCache` — потокобезопасный LRU-кэш с TTL-поддержкой
- Размер по умолчанию: **500** записей, TTL: **600** секунд
- SHA256-хеширование ключей кэша (method + endpoint + data)
- Статистика: hits, misses, hit_rate
- Инструмент MCP: `clear_mcp_cache()` — очистка кэша

### Batch операции

- `BatchRequest` — параллельное выполнение до N запросов одновременно
- Семафор (`asyncio.Semaphore`) для ограничения конкурентности
- Параметры: `max_concurrent`, `fail_fast`, `priority`
- Инструмент MCP: `batch_execute()` — выполнение пачки запросов

### Rate Limiting

- `RateLimiter` — алгоритм **token bucket**
- Настраиваемый: `requests_per_second` (по умолчанию 10), `burst_size` (по умолчанию 20)
- Автоматическое ожидание при исчерпании токенов
- Статистика: total_requests, rejected_requests, average_wait_time

### Обработка ошибок

- `ErrorClassifier` — классификация ошибок по категориям: `NETWORK`, `TIMEOUT`, `AUTH`, `RATE_LIMIT`, `SERVER`, `CLIENT`
- `EnhancedError` — детальная информация: категория, тяжесть, восстанавливаемость, подсказка восстановления
- `RetryStrategy` — повторные попытки с **exponential backoff** и jitter
  - Максимальное количество попыток: 3
  - Задержка: 1с → 2с → 4с (с рандомизацией)
  - Категории без retry: `AUTH`
- Маппинг HTTP-статусов: 401, 403 → AUTH; 429 → RATE_LIMIT; 500, 502, 503 → SERVER; 504 → TIMEOUT

### Новые MCP инструменты

| Инструмент | Описание |
|-----------|----------|
| `batch_execute()` | Параллельное выполнение запросов |
| `get_mcp_stats()` | Статистика кэша, rate limiter, запросов |
| `clear_mcp_cache()` | Очистка локального MCP-кэша |

---

## Транспорт и оптимизация (v6.3.0)

### MCP-транспорт

По умолчанию HexStrike MCP работает через **stdio**: OpenCode порождает процесс
`OpenCodeStart.sh` и общается по stdin/stdout. При длительных сканах (60+ c)
используйте streamable-http/sse — соединение не рвётся.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | `stdio` \| `sse` \| `streamable` \| `http` (`http` = алиас `streamable`) |
| `MCP_HOST` | `127.0.0.1` | Адрес привязки MCP-сервера (для sse/streamable) |
| `MCP_PORT` | `9010` | Порт MCP-сервера (отдельно от Flask `8888`) |

**Включение streamable-http:**

```bash
sudo systemctl enable --now hexstrike-mcp   # поднимает MCP на :9010
```

Затем переключите OpenCode на remote-подключение в `~/.opencode/opencode.jsonc`:

```jsonc
"hexstrike": {
  "type": "remote",
  "url": "http://127.0.0.1:9010/mcp",
  "enabled": true
}
```

Эндпоинты: streamable-http → `…/mcp`, SSE → `…/sse`. CLI-флаги `--transport`,
`--host`, `--port` переопределяют env.

### Оптимизатор контекста

Постобработка вывода инструментов перед возвратом агенту: меньше контекста →
быстрее ответы и экономия токенов. Включён по умолчанию, консервативные пороги
(короткие строки < 1000 символов не трогаются, LLM-суммаризации нет).

| Переменная | По умолчанию | Описание |
|---|---|---|
| `MCP_OPTIMIZER_ENABLED` | `true` | Вкл/выкл оптимизатор |
| `MCP_OPTIMIZER_MAX_CHARS` | `20000` | Порог трюнкации длинного вывода (head+tail) |
| `MCP_OPTIMIZER_DEDUP` | `true` | Дедупликация одинаковых строк |
| `MCP_OPTIMIZER_STRIP_ANSI` | `true` | Удаление ANSI/escape-кодов и прогресс-баров |

Полностью обратимо — установите `MCP_OPTIMIZER_ENABLED=false`, чтобы отключить.

---

## Тесты и разработка

Начиная с v6.3.0 проект покрыт unit-тестами (pytest) на «чистые» функции без I/O. В v6.4.0 тестовое покрытие масштабно расширено: добавлены тесты на весь пакет `hexstrike_guardrails/`, `pentest_session.py` и на legacy-эксплойт-генераторы. В v6.4.5 добавлены тесты на MCP-консолидацию (профили, глаголы, алиасы, guardrails для metasploit). Всего **456 тестов** (115 → 415 → 456).

### Установка dev-зависимостей

```bash
pip install -r requirements-dev.txt
```

### Запуск тестов

```bash
pytest            # полный прогон с покрытием (~9 c)
pytest --no-cov   # без покрытия (быстрее)
pytest -m guardrails   # только guardrails-тесты (300 шт.)
pytest -m slow         # только slow (импорт 742КБ hexstrike_server)
```

### Покрытие

| Модуль | Покрытие |
|---|---|
| `hexstrike_guardrails/tiers.py` | 96% |
| `hexstrike_guardrails/scope.py` | 96% |
| `hexstrike_guardrails/_db.py` | 95% |
| `hexstrike_guardrails/rate_limiter.py` | 94% |
| `hexstrike_guardrails/audit.py` | 85% |
| `hexstrike_guardrails/state.py` | 87% |
| `hexstrike_guardrails/blueprint.py` | 66% |
| `pentest_session.py` | 70% |
| `hexstrike_mcp.py` | 42% |
| `hexstrike_server.py` | 14% (монолит 17.5k строк, точечное покрытие) |

Жёсткий порог `--cov-fail-under=70` вводится в v7.0.0 (T6); сейчас CI гоняет тесты только на зелёность.

### CI

GitHub Actions (`.github/workflows/ci.yml`, Python 3.13) прогоняет `pytest` на каждый push в `master` и на pull request. С v6.4.0 используются actions на Node.js 24 (`checkout@v6`, `setup-python@v6`) — без deprecated-предупреждений Node 20.

---

## Guardrails и сессии (v6.4.0)

Релиз добавляет слой безопасности и контроля над действиями агента: scope-валидация целей, классификация инструментов по опасности, ограничение нагрузки, аварийный стоп-кран и аудит-лог. Плюс персистентные пентест-сессии с CVSS-скорингом и markdown-отчётами. Все данные — в SQLite, переживают рестарт. Подключается автоматически через `_register_optional_blueprints()` в `hexstrike_server.py`; если пакет недоступен — сервер стартует без guardrails.

### Scope-валидация

Контроль области тестирования: allowlist целей задаётся на сессию, вызов вне scope блокируется **до выполнения**. Пустой scope (по умолчанию) = allow-all.

```bash
# Установить scope
curl -X POST http://127.0.0.1:8888/api/guardrails/scope \
  -H "Content-Type: application/json" \
  -d '{"rules": ["192.168.0.0/16", "example.com", "*.corp"]}'

# Проверить таргет
curl -X POST http://127.0.0.1:8888/api/guardrails/validate \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.5"}'
# {"in_scope": true, "matched_rule": "192.168.0.0/16", ...}
```

Поддерживаемые форматы правил: CIDR (`192.168.0.0/24`, `::1/128`), bare IP (`10.0.0.5` → `/32`), wildcard (`*.example.com`), regex (`r:^.*\.internal$`, cap 256 символов против ReDoS), hostname (`example.com`, case-insensitive).

### Классификация инструментов

Все 149 инструментов размечены на три уровня опасности:

| Уровень | Что это | Примеры |
|---|---|---|
| 🟢 **SAFE** | Пассивная разведка, без трафика на цель | subfinder, httpx, amass, whois, strings |
| 🟠 **INTRUSIVE** | Активное сканирование, создаёт трафик | nmap, nuclei, gobuster, nikto, ffuf |
| 🔴 **DESTRUCTIVE** | Эксплойты, брутфорс, изменения | sqlmap, hydra, metasploit, john, hashcat |

Destructive требует явного подтверждения (через `confirmed: true` в запросе или env `GUARDRAILS_AUTOCONFIRM=1`). Special-case: `nmap + aggressive=true` автоматически повышается до DESTRUCTIVE. Список: `GET /api/guardrails/tiers`.

### Ограничение нагрузки

Per-target caps — не «кладёт» целевую систему, не триггерит WAF/IDS:

| Переменная | По умолчанию | Описание |
|---|---|---|
| `GUARDRAILS_MAX_CONCURRENT` | `5` | Лимит одновременных запросов на цель |
| `GUARDRAILS_MAX_RPS` | `10` | Лимит запросов в секунду на цель |
| `GUARDRAILS_RATE_TIMEOUT` | `0.0` | Сколько ждать блокирующе при превышении (сек) |

Per-target изоляция — разные цели не мешают друг другу. Stale-targets чистятся автоматически через `cleanup_stale(ttl=600s)`.

### Kill switch

Аварийный стоп-кран: один HTTP-вызов останавливает все процессы сессии или глобально. SIGTERM → grace period → SIGKILL.

```bash
curl -X POST http://127.0.0.1:8888/api/guardrails/kill-all -d '{"reason":"emergency"}'
curl -X POST http://127.0.0.1:8888/api/guardrails/reset
```

Флаг persists в SQLite (`metadata` table) — виден всем воркерам Gunicorn. На health-панели — мигающая stat-card Kill Switch (IDLE/ENGAGED).

### Audit log

Каждое решение guardrails (allow или block) пишется в SQLite: кто/что/когда/какой tier/результат. Доступно через API и в `/health`-панели.

```bash
curl http://127.0.0.1:8888/api/guardrails/audit?limit=20
curl http://127.0.0.1:8888/api/session/{id}/audit
```

### Персистентные пентест-сессии

Сессия привязана к цели, аккумулирует находки всех инструментов, автоматически считает CVSS, генерирует готовый markdown-отчёт. Данные переживают рестарт.

```bash
# Создать сессию
curl -X POST http://127.0.0.1:8888/api/session/create \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","scope_rules":["example.com"]}'
# {"session_id":"abc123def456...", ...}

# Добавить находку (CVSS считается автоматически)
curl -X POST http://127.0.0.1:8888/api/session/abc123/finding \
  -H "Content-Type: application/json" \
  -d '{"tool":"sqlmap","vuln_type":"sqli","title":"Login bypass","endpoint":"/login"}'
# {"cvss_score":9.8,"severity":"critical",...}

# Сгенерировать markdown-отчёт
curl -s "http://127.0.0.1:8888/api/session/abc123/report?format=markdown" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['report'])"
```

Отчёт содержит: executive summary, risk overview, attack surface (порты/технологии/endpoints из `recon`), детальные находки с CVSS, remediation priority, audit trail. CVSS-маппинг: `sqli/rce=9.8`, `ssrf=8.8`, `xxe=8.6`, `idor=6.5`, `xss_reflected=6.1`, `xss_stored=7.4`. Прочие эндпоинты: `POST /api/session/{id}/close`, `GET /api/session/list`, `POST /api/session/{id}/recon`, `POST /api/session/{id}/finding/{fid}/confirm|fp`.

### Конфигурация

| Переменная | По умолчанию | Описание |
|---|---|---|
| `GUARDRAILS_DB` | `data/hexstrike_sessions.db` | Путь к SQLite-базе |
| `GUARDRAILS_MAX_CONCURRENT` | `5` | Concurrent запросов на цель |
| `GUARDRAILS_MAX_RPS` | `10` | Запросов/сек на цель |
| `GUARDRAILS_RATE_TIMEOUT` | `0.0` | Блокирующий таймаут (сек) |
| `GUARDRAILS_AUTOCONFIRM` | `0` | `1` = destructive без подтверждения |

Работает out-of-the-box: пустой scope = allow-all, авто-подтверждение выключено, лимиты 5/10. SQLite-база и `data/` каталог создаются автоматически при первом запросе.

### Health-панель

`/health` расширен тремя новыми секциями: **GUARDRAILS** (kill switch state, rate limits, scope pills, tier distribution), **RECENT SESSIONS** (severity breakdown), **RECENT AUDIT** (последние события с tier-бейджами). В верхней панели появилась stat-card Kill Switch (IDLE/ENGAGED).

---

## MCP-консолидация и профили (v6.4.5)

Релиз v6.4.5 «Streamline» решает три проблемы сразу: агент мог запустить скан «не туда» (теперь guardrails из v6.4.0 блокируют), перегрузить цель дублирующими инструментами (теперь глаголы вместо близнецов), или просто сожрать половину контекстного окна LLM описаниями тулов (теперь `HEXSTRIKE_MCP_PROFILE`).

### 6 «глаголов» вместо 14 близнецов

Раньше 14 MCP-инструментов делали почти одно и то же (3 разные тулы для скана портов, 3 для брутфорса директорий, и т.д.). Теперь — по одному глаголу на класс задач, с параметром `tool=auto` (по умолчанию сервер сам выбирает оптимальный CLI):

| Глагол | Заменяет | Что делает |
|---|---|---|
| `port_scan` | nmap / nmap-advanced / rustscan / masscan | Скан портов (mode=fast/full/stealth/udp) |
| `subdomain_enum` | amass / subfinder | Поддомены (source=passive/active/all) |
| `http_probe` | httpx / katana | HTTP liveness / краулинг / tech-detect |
| `directory_brute` | gobuster / ffuf / dirsearch | Брутфорс директорий / vhost / fuzzing |
| `web_vuln_scan` | nuclei / nikto / wpscan | Веб-уязвимости (profile=generic/cms/legacy/wordpress) |
| `cloud_audit` | prowler / trivy / kube-hunter / checkov | Аудит облака (scope=aws/k8s/docker/iac/all) |

Каждый глагол — тонкая диспетчерская обёртка над уже существующими `/api/tools/*` роутами; бизнес-логика не дублируется. Старые имена (`nmap_scan`, `gobuster_scan` и 12 других) сохранены как deprecated aliases до v6.5.0.

### `metasploit_run` под guardrails

Новый first-class MCP-инструмент для Metasploit с явной маркировкой `tier=DESTRUCTIVE`. Ранее metasploit был доступен только через `execute_command` (свободный shell-вызов) и **обходил guardrails** — критический зазор в этическом позиционировании, особенно после инцидента с бронированием отелей 2026-06-23 (когда HexStrike+Claude использовали для реальной атаки). Теперь `metasploit_run` требует активного scope и tier=destructive; вызов вне scope блокируется до выполнения, audit-лог пишется всегда.

### `HEXSTRIKE_MCP_PROFILE` — экономия токенов

Server-side фильтрация инструментов через env-переменную. Работает в любом MCP-клиенте (OpenCode, Claude Desktop, Cursor, Cline), не зависит от Anthropic quasi-static (которое не работает с OpenAI-compatible API вроде GLM-5.2).

| Профиль | Инструментов | ~Токенов | Назначение |
|---|---|---|---|
| `minimal` | 4 | ~1 300 | 4 meta: execute / smart_scan / analyze / batch |
| `recon` | 7 | ~2 400 | + `port_scan`, `subdomain_enum`, `http_probe` |
| `web` | 9 | ~3 100 | + `directory_brute`, `web_vuln_scan` |
| `exploit` | 13 | ~3 900 | + `sqlmap`, `hydra`, `metasploit_run`, `cloud_audit` |
| `full` (default) | 13 новых + 14 aliases = 32 | ~6 500 | Обратная совместимость |

Дополнительно `HEXSTRIKE_MCP_ALIASES=0` прячет 14 deprecated имён даже в `full`, оставляя только 13 современных глаголов (~4 000 токенов).

Пример OpenCode config с lean-профилем:

```jsonc
"mcp": {
  "hexstrike": {
    "type": "local",
    "command": ["python", "hexstrike_mcp.py"],
    "environment": { "HEXSTRIKE_MCP_PROFILE": "recon" }
  }
}
```

### Совместимость

На 100% обратно совместимо. Default поведение (`HEXSTRIKE_MCP_PROFILE=full + HEXSTRIKE_MCP_ALIASES=1`) сохраняет все 25 существующих имён инструментов + добавляет 7 новых = 32. Существующие AGENTS.md, сохранённые диалоги, кастомные промпты работают без изменений. Экономия токенов — **opt-in** через lean-профили.

---

## Синхронизация с upstream

Upstream `0x4m4/hexstrike-ai` фактически заморожен, поэтому регулярная
синхронизация не требуется. Скрипт `scripts/sync-upstream.sh` используется в
maintenance-режиме — для точечного подтягивания фиксов CVE/безопасности с
**сохранением нашего набора файлов**.

```bash
bash scripts/sync-upstream.sh
```

Что делает скрипт:

1. Добавляет remote `upstream` и делает `fetch`.
2. Создаёт изолированную ветку `upstream-sync` от `master`.
3. Сливает `upstream/master` (`--allow-unrelated-histories`, т.к. репозиторий независимый, а не GitHub-fork).
4. **Автоматически защищает** наш набор (восстанавливает из `HEAD`):
   `README.md`, `deploy.sh`, `VERSION`, `CHANGELOG.md`, `templates/`,
   `requirements.txt`, `requirements-dev.txt`, `OpenCodeStart.sh`,
   `hexstrike_mcp.py`, `hexstrike_optimizer.py`, `hexstrike_guardrails/`,
   `pentest_session.py`, `schemas/`, `scripts/`, `tests/`, `.github/`,
   `pytest.ini`, `.gitignore`.
5. **НЕ трогает** `hexstrike_server.py` — оставляет conflict-маркеры для
   ручного ревью (там наши правки health-панели).
6. Генерирует `MERGE_UPSTREAM_REPORT.md` со списком конфликтов и защищённых файлов.
7. **Пауза**: скрипт не делает auto-commit — ревью и коммит выполняются вручную.

После запуска разрешите маркеры (особенно в `hexstrike_server.py`), прогоните
`pytest`, закоммитьте и слейте ветку `upstream-sync` в `master`.
