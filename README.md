

# HexStrike AI — Chumikov Sec Fork

Форк [HexStrike-AI](https://github.com/0x4m4/hexstrike-ai): REST-API + MCP-мост для управления security-инструментами (nmap, nuclei, sqlmap, gobuster, metasploit и 140+ другими) из AI-агентов — OpenCode, Claude Desktop, Cursor, Cline. Проект развивается самостоятельно: асинхронное исполнение сканов, слой guardrails, персистентные сессии, тесты и CI.

Проект рассчитан на **авторизованный** пентест и security-исследования. История интеграции с OpenCode — в [моей статье на Habr](https://habr.com/ru/articles/985450/).

---

# Содержание

1. [Возможности](#возможности)
2. [Установка и обновление](#установка-и-обновнение)
3. [Архитектура](#архитектура)
4. [Структура проекта](#структура-проекта)
5. [Деплой](#деплой)
6. [Панель мониторинга](#панель-мониторинга)
7. [Подключение AI-агентов](#подключение-ai-агентов)
8. [Guardrails и пентест-сессии](#guardrails-и-пентест-сессии)
9. [MCP: инструменты и профили](#mcp-инструменты-и-профили)
10. [Транспорт и оптимизация](#транспорт-и-оптимизация)
11. [Тесты и разработка](#тесты-и-разработка)
12. [Синхронизация с upstream](#синхронизация-с-upstream)

---

## Возможности

- **Единый REST API** (`http://127.0.0.1:8888`) поверх 140+ CLI-инструментов: сканирование, брутфорс, эксплойты, разведка, CTF-форензика, аудит облака
- **MCP-мост** (`hexstrike_mcp.py`, FastMCP) — те же возможности в виде инструментов модельного контекст-протокола для AI-агентов
- **Guardrails**: scope-валидация целей, классификация инструментов по опасности (SAFE/INTRUSIVE/DESTRUCTIVE), per-target rate limiting, kill switch, audit log
- **Персистентные пентест-сессии**: находки инструментов аккумулируются в SQLite, CVSS-скоринг считается автоматически, отчёты генерируются в markdown
- **Асинхронное исполнение**: долгие сканы выполняются в process pool, статус задач персистентен и переживает рестарт воркеров
- **Безопасное исполнение команд**: argv-list + `shell=False`, валидация target/url, redaction секретов в логах
- **Экономия токенов**: постобработка вывода инструментов (дедупликация, трюнкация, strip ANSI) и lean-профили MCP-инструментов
- **Эксплуатация**: gunicorn + systemd (автоперезапуск, OOM-политики, лимиты памяти), HTML-панель мониторинга, unit-тесты и CI

## Установка и обновление

Требования: Kali Linux, пакет `hexstrike-ai`, Python >= 3.10.

```bash
sudo apt install hexstrike-ai
git clone https://github.com/Chumikov/hexstrike_chumikov_sec.git
cd hexstrike_chumikov_sec
sudo bash deploy.sh
```

Обновление — то же самое: `git pull && sudo bash deploy.sh`.

Проверка:

```bash
systemctl status hexstrike
curl http://127.0.0.1:8888/health
```

## Архитектура

Два компонента:

```
AI-агент (OpenCode / Claude / Cursor / Cline)
   │  MCP (stdio или streamable-http/sse, :9010)
   ▼
hexstrike_mcp.py  ──HTTP──►  hexstrike_server.py (Flask + gunicorn, :8888)
                                     │
                                     ├─ hexstrike_guardrails/  (scope, tiers, rate, kill, audit)
                                     ├─ pentest_session.py     (сессии, CVSS, отчёты)
                                     ├─ task_store.py          (async-задачи в SQLite)
                                     └─ subprocess: nmap, nuclei, sqlmap, metasploit, …
```

- **Сервер** — Flask-приложение под gunicorn (gthread-воркеры с потоками: долгие сканы не замораживают API, автоперезапуск по `--max-requests` с jitter от утечек памяти, systemd-интеграция с OOM-политиками и RAM-scaled лимитами). Слушает только `127.0.0.1`
- **MCP-клиент** — FastMCP-сервер, мост между агентом и REST API: кэш, rate limiting, retry с exponential backoff, batch-запросы
- **SQLite** (`data/hexstrike_sessions.db`) — единое хранилище guardrails, сессий, audit log и async-задач; всё переживает рестарт

## Структура проекта

| Файл | Назначение |
|---|---|
| `hexstrike_server.py` | Flask REST API — 156+ маршрутов, обёртки над security-инструментами |
| `hexstrike_mcp.py` | MCP-сервер на FastMCP — мост между AI-агентами и REST API |
| `hexstrike_optimizer.py` | Оптимизатор контекста/токенов для вывода инструментов |
| `hexstrike_guardrails/` | Слой безопасности: scope/tier/rate/kill/audit (9 модулей) |
| `pentest_session.py` | Персистентные пентест-сессии, CVSS, отчёты |
| `task_store.py` | Персистентное хранилище async-задач в SQLite |
| `schemas/hexstrike_sessions.sql` | DDL SQLite-таблиц |
| `data/` | Runtime SQLite (gitignored) |
| `deploy.sh` | Полный деплой: venv, зависимости, systemd, проверка |
| `requirements.txt` / `requirements-dev.txt` | Зависимости (runtime / pytest) |
| `OpenCodeStart.sh` | Автозапуск сервера + MCP-клиента для OpenCode |
| `templates/health_panel.html` | Шаблон HTML-панели мониторинга |
| `scripts/sync-upstream.sh` | Maintenance-синхронизация с upstream |
| `tests/` | Unit-тесты (pytest) |
| `scripts/synthetic_lab.py` | Синтетический полигон (95 проверок): живые цели (SQLi/XSS/redirect/soft-404/TLS/чёрная дыра/медленная/закрытый порт), MCP-слой по stdio, зависания, kill-семантика, auth-инстанс |
| `scripts/mcp_client.py` | Минимальный stdio JSON-RPC клиент для полигона |
| `.github/workflows/ci.yml` | CI: pytest на каждый push/PR |
| `VERSION` / `CHANGELOG.md` | Версия (SemVer) и история релизов |

## Деплой

`deploy.sh` выполняет всё автоматически: проверка окружения (root, `hexstrike-ai`, Python, PyPI) → копирование файлов → venv с `--system-site-packages` → зависимости → gunicorn wrapper → освобождение порта 8888 → systemd unit → `enable` + `start` → ожидание health-check → итоговая сводка. Дополнительно создаётся выключенный по умолчанию юнит `hexstrike-mcp.service` (для streamable/sse-транспорта). При ошибке на любом шаге выводит `systemctl status` и `journalctl`.

Ручная проверка после деплоя:

```bash
systemctl status hexstrike
curl http://127.0.0.1:8888/health
pgrep -c gunicorn
```

## Панель мониторинга

`/health` отдаёт HTML-панель с тёмным дизайном: прогресс-бары по категориям инструментов, сетка статуса (установлен/отсутствует; `INFO` — просто сведения о наличии в системе), системные метрики (CPU, RAM, Disk, Network). Если установлен пакет guardrails — также секции **GUARDRAILS** (kill switch, rate limits, scope, tier-распределение), **RECENT SESSIONS** (находки по severity) и **RECENT AUDIT** (последние события с tier-бейджами).

`/health?json` или `Accept: application/json` — JSON для API (включая блок `guardrails`).

Версию сервера можно узнать так:

```bash
curl -s http://127.0.0.1:8888/health?json | python3 -c "import sys,json; print(json.load(sys.stdin)['version'])"
```

## Подключение AI-агентов

### OpenCode (stdio, по умолчанию)

Файл `/home/kali/.opencode/opencode.jsonc` (или в `~/.config/opencode`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "experimental": { "mcp_timeout": 1200000 },
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

Для долгих сканов предпочтительнее streamable-http — см. [«Транспорт и оптимизация»](#транспорт-и-оптимизация).

### Другие MCP-клиенты

Любой клиент, умеющий stdio или streamable-http/sse, подключается к `hexstrike_mcp.py` напрямую. Профили инструментов (`HEXSTRIKE_MCP_PROFILE`) работают во всех клиентах.

## Guardrails и пентест-сессии

Слой контроля над действиями агента. Подключается автоматически; если пакет недоступен — сервер стартует без guardrails. Все данные — в SQLite, переживают рестарт.

### Scope-валидация

Allowlist целей на сессию; вызов вне scope блокируется **до выполнения**. Пустой scope (по умолчанию) = allow-all. Форматы правил: CIDR, bare IP, wildcard (`*.example.com`), regex (`r:^…$`), hostname.

```bash
curl -X POST http://127.0.0.1:8888/api/guardrails/scope \
  -H "Content-Type: application/json" \
  -d '{"rules": ["192.168.0.0/16", "example.com", "*.corp"]}'

curl -X POST http://127.0.0.1:8888/api/guardrails/validate \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.5"}'
# {"in_scope": true, "matched_rule": "192.168.0.0/16", ...}
```

### Классификация инструментов

Все инструменты размечены на три уровня опасности:

| Уровень | Что это | Примеры |
|---|---|---|
| 🟢 **SAFE** | Пассивная разведка, без трафика на цель | subfinder, httpx, amass, whois, strings |
| 🟠 **INTRUSIVE** | Активное сканирование, создаёт трафик | nmap, nuclei, gobuster, nikto, ffuf |
| 🔴 **DESTRUCTIVE** | Эксплойты, брутфорс, изменения | sqlmap, hydra, metasploit, john, hashcat |

DESTRUCTIVE требует явного подтверждения (`confirmed: true` в запросе или env `GUARDRAILS_AUTOCONFIRM=1`). `nmap` с `aggressive=true` автоматически повышается до DESTRUCTIVE. Список: `GET /api/guardrails/tiers`.

### Ограничение нагрузки и kill switch

Per-target caps, чтобы не «уложить» цель и не триггерить WAF/IDS:

| Переменная | По умолчанию | Описание |
|---|---|---|
| `GUARDRAILS_MAX_CONCURRENT` | `5` | Лимит одновременных запросов на цель |
| `GUARDRAILS_MAX_RPS` | `10` | Лимит запросов в секунду на цель |
| `GUARDRAILS_RATE_TIMEOUT` | `0.0` | Блокирующее ожидание при превышении (сек) |

Лимиты применяются **на gunicorn-воркер** (состояние in-process); при sync-воркерах фактическая конкурентность на цель не превышает числа воркеров.

Kill switch — аварийный стоп-кран: один HTTP-вызов останавливает все процессы сессии или глобально (SIGTERM → grace period → SIGKILL). Флаг персистентен, виден всем воркерам gunicorn.

```bash
curl -X POST http://127.0.0.1:8888/api/guardrails/kill-all -d '{"reason":"emergency"}'
curl -X POST http://127.0.0.1:8888/api/guardrails/reset
```

### Audit log

Каждое решение guardrails (allow или block) пишется в SQLite: кто/что/когда/какой tier/результат. Доступно через API и в health-панели.

```bash
curl http://127.0.0.1:8888/api/guardrails/audit?limit=20
curl http://127.0.0.1:8888/api/session/{id}/audit
```

### Пентест-сессии

Сессия привязана к цели, аккумулирует находки всех инструментов, автоматически считает CVSS и генерирует markdown-отчёт.

```bash
curl -X POST http://127.0.0.1:8888/api/session/create \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","scope_rules":["example.com"]}'
# {"session_id":"abc123def456...", ...}

curl -X POST http://127.0.0.1:8888/api/session/abc123/finding \
  -H "Content-Type: application/json" \
  -d '{"tool":"sqlmap","vuln_type":"sqli","title":"Login bypass","endpoint":"/login"}'
# {"cvss_score":9.8,"severity":"critical",...}

curl -s "http://127.0.0.1:8888/api/session/abc123/report?format=markdown" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['report'])"
```

## MCP: инструменты и профили

### Глаголы

Основной набор MCP-инструментов — «глаголы», по одному на класс задач, с параметром `tool=auto` (сервер сам выбирает оптимальный CLI):

| Глагол | Заменяет | Что делает |
|---|---|---|
| `port_scan` | nmap / rustscan / masscan | Скан портов (mode=fast/full/stealth/udp) |
| `subdomain_enum` | amass / subfinder | Поддомены (source=passive/active/all) |
| `http_probe` | httpx / katana | HTTP liveness / краулинг / tech-detect |
| `directory_brute` | gobuster / ffuf / dirsearch | Брутфорс директорий / vhost / fuzzing |
| `web_vuln_scan` | nuclei / nikto / wpscan | Веб-уязвимости (profile=generic/cms/…) |
| `cloud_audit` | prowler / trivy / kube-hunter / checkov | Аудит облака (scope=aws/k8s/docker/iac/all) |

`metasploit_run` — отдельный инструмент с маркировкой `tier=DESTRUCTIVE`: требует активного scope и подтверждения, вызов вне scope блокируется, audit-лог пишется всегда.

Плюс meta-инструменты: `execute`, `smart_scan`, `analyze`, `batch_execute` (параллельные запросы с семафором), `get_mcp_stats`, `clear_mcp_cache`. Legacy-имена инструментов сохранены как deprecated aliases.

### Профили `HEXSTRIKE_MCP_PROFILE`

Server-side фильтрация инструментов через env-переменную — меньше описаний в контексте, меньше токенов. Работает в любом MCP-клиенте.

| Профиль | Инструментов | ~Токенов | Назначение |
|---|---|---|---|
| `minimal` | 4 | ~1 300 | meta: execute / smart_scan / analyze / batch |
| `recon` | 7 | ~2 400 | + `port_scan`, `subdomain_enum`, `http_probe` |
| `web` | 9 | ~3 100 | + `directory_brute`, `web_vuln_scan` |
| `exploit` | 13 | ~3 900 | + `sqlmap`, `hydra`, `metasploit_run`, `cloud_audit` |
| `full` (default) | все + aliases | ~6 500 | Обратная совместимость |

`HEXSTRIKE_MCP_ALIASES=0` прячет deprecated aliases даже в `full`.

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

### Кэш, rate limiting, retry

- `LRUCache` — потокобезопасный LRU с TTL (500 записей / 600 сек), SHA256-ключи, статистика hit rate
- `RateLimiter` — token bucket (10 rps, burst 20), автожидание при исчерпании
- `ErrorClassifier` + retry с exponential backoff и jitter (1с → 2с → 4с; AUTH-ошибки без retry)

## Транспорт и оптимизация

### MCP-транспорт

По умолчанию — **stdio**. Для длительных сканов (60+ c) используйте streamable-http/sse — соединение не рвётся:

| Переменная | По умолчанию | Описание |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | `stdio` \| `sse` \| `streamable` \| `http` (алиас `streamable`) |
| `MCP_HOST` | `127.0.0.1` | Адрес привязки MCP-сервера |
| `MCP_PORT` | `9010` | Порт MCP-сервера (отдельно от Flask `8888`) |

```bash
sudo systemctl enable --now hexstrike-mcp   # поднимает MCP на :9010
```

```jsonc
"hexstrike": {
  "type": "remote",
  "url": "http://127.0.0.1:9010/mcp",
  "enabled": true
}
```

CLI-флаги `--transport`, `--host`, `--port` переопределяют env.

### Оптимизатор контекста

Постобработка вывода инструментов перед возвратом агенту: меньше контекста → быстрее ответы и экономия токенов. Включён по умолчанию, консервативные пороги (короткие строки < 1000 символов не трогаются, LLM-суммаризации нет).

| Переменная | По умолчанию | Описание |
|---|---|---|
| `MCP_OPTIMIZER_ENABLED` | `true` | Вкл/выкл оптимизатор |
| `MCP_OPTIMIZER_MAX_CHARS` | `20000` | Порог трюнкации длинного вывода (head+tail) |
| `MCP_OPTIMIZER_DEDUP` | `false` | Дедупликация подряд идущих строк. **Выключена по умолчанию**: схлопывание повторов тихо искажает позиционно-значимые данные (ASCII-битмапы, hex-дампы). Включайте только для заведомо текстового вывода |
| `MCP_OPTIMIZER_STRIP_ANSI` | `true` | Удаление ANSI-кодов и прогресс-баров |

### Переменные окружения сервера

| Переменная | По умолчанию | Описание |
|---|---|---|
| `HEXSTRIKE_MAX_OUTPUT_BYTES` | `10485760` | Потолок захвата stdout+stderr подпроцесса; при превышении процесс убивается, результат помечается `output_truncated` (защита от flooding-бинарников) |
| `HEXSTRIKE_HTTPX_BIN` | — | Явный путь к binary httpx. По умолчанию сервер функционально различает projectdiscovery/httpx и Python-клиент `httpx` (Kali-пакет `python3-httpx`): первый получает цели через stdin и полный набор флагов, второй используется как ограниченный fallback (URL позиционно), а tech-detect честно отвечает 501 с подсказкой установить PD-вариант |
| `HEXSTRIKE_API_KEY` / `HEXSTRIKE_REQUIRE_AUTH` | — / `false` | API-аутентификация (`X-API-Key` / `Authorization: Bearer`) |

## Синтетический полигон

`scripts/synthetic_lab.py` — end-to-end проверка перед/после деплоя (95 проверок): поднимает одноразовый полигон на 127.0.0.1 (веб-сервер с настоящей SQLi, reflected XSS, redirect-цепочкой, soft-404 зоной, self-signed TLS, чёрной дырой, медленным и закрытым портами) и прогоняет функциональные сценарии реальными инструментами, MCP-слой по stdio (путь агента), guardrails-сценарии, инъекционную батарею, матрицу зависаний, freeze-пробу, дрейф флагов инструментов, kill-семантику, auth-режим и выживание async-задач.

```bash
python3 scripts/synthetic_lab.py             # полный прогон (~10 мин)
python3 scripts/synthetic_lab.py --quick     # без медленных сканов
HEXSTRIKE_LAB_SMOKE=1 sudo bash deploy.sh    # post-deploy smoke
```

## Тесты и разработка

Проект покрыт unit-тестами (pytest) на «чистые» функции без I/O: guardrails, валидация входных данных, task store, MCP-консолидация, парсеры, эксплойт-генераторы.

```bash
pip install -r requirements-dev.txt

pytest                 # полный прогон с покрытием (~10 c)
pytest --no-cov        # без покрытия (быстрее)
pytest -m guardrails   # только guardrails-тесты
pytest -m slow         # только slow (импорт 742КБ hexstrike_server)
```

Высокое покрытие: `hexstrike_guardrails/` (66–96%), `pentest_session.py` (~70%). `hexstrike_server.py` покрыт точечно — монолит на 17.5k строк.

CI: GitHub Actions (Python 3.13) прогоняет `pytest` на каждый push в `master` и на pull request.

История релизов и изменения по версиям — в [CHANGELOG.md](CHANGELOG.md). Версионирование — SemVer: файл `VERSION`, git-теги `vX.Y.Z` соответствуют релизам на GitHub.

## Синхронизация с upstream

Upstream `0x4m4/hexstrike-ai` фактически заморожен, поэтому регулярная синхронизация не требуется. Скрипт `scripts/sync-upstream.sh` используется в maintenance-режиме — для точечного подтягивания фиксов CVE/безопасности с **сохранением нашего набора файлов**.

```bash
./scripts/sync-upstream.sh          # проверить наличие новых релизов upstream
./scripts/sync-upstream.sh apply <tag>   # подтянуть конкретный релиз
./scripts/sync-upstream.sh status    # состояние локальной синхронизации
```

## Лицензия

MIT — см. [LICENSE](LICENSE), с атрибуцией m0x4m4 (оригинальный проект) → netcuter (PL fork) → Chumikov.
