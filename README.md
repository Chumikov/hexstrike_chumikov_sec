# HexStrike AI — Chumikov Sec Fork

В своей статье https://habr.com/ru/articles/985450/ я рассмотрел интеграцию Hexstrike-AI и OpenCode в Kali Linux. С того времени вышло очень много обновлений OpenCode и всего 2 или 3 патча безопасности для HexStrike. При этом, работа указанной связки была крайне нестабильной и местами крайне медленной. Ждать обещанную 7 версию Hexstrike я не стал и решил внести несколько правок в Hexstrike и неформально получить собственную версию 6.1 данного решения.

Тут я делюсь с вами своими исправлениями и улучшениями. Планирую развивать данный репо вплоть до выхода Hexstrike 7.0.

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
| `deploy.sh` | Полный деплой: venv, зависимости, systemd, проверка |
| `requirements.txt` | Зависимости Python с фиксированными версиями |
| `requirements-dev.txt` | Dev/test-зависимости (pytest, pytest-cov) |
| `OpenCodeStart.sh` | Автозапуск сервера + MCP-клиента для OpenCode |
| `templates/health_panel.html` | Шаблон HTML-панели мониторинга |
| `scripts/sync-upstream.sh` | Maintenance-синхронизация с upstream `0x4m4/hexstrike-ai` |
| `tests/` | Unit-тесты (pytest) |
| `.github/workflows/ci.yml` | CI: pytest на каждый push/PR |

---

## Деплой

### Архитектура сервера

По умолчанию, Hexstrike 6.0 использует Flask, который использует встроенный development-сервер (`app.run()`) — он однопоточный, не имеет автоперезапуска, подвержен утечкам памяти, не переживает падения. Для фреймворка, который держит открытыми subprocess'ы Nmap/Nuclei/SQLMap по несколько минут, это неприемлемо.

### Преимущества Gunicorn перед Flask dev-сервером

- 2 worker-процесса вместо одного — параллельная обработка запросов, один долгий скан не блокирует API
- Автоперезапуск worker'ов после 1000 запросов (`--max-requests`) — защита от утечек памяти
- systemd-интеграция — автозапуск при загрузке, автоматический рестарт при падении (`Restart=on-failure`)
- Graceful reload — `kill -HUP` перезапускает worker'ов без даунтайма
- Таймаут 300с на уровне сервера — защита от зависших запросов

### Скрипт деплоя

`deploy.sh` выполняет все шаги автоматически:

1. Проверка root-прав и наличия `hexstrike-ai`, Python >= 3.10
2. Копирование всех файлов проекта (`hexstrike_server.py`, `hexstrike_mcp.py`, `templates/`, `VERSION`, `requirements.txt`)
3. Создание venv с `--system-site-packages` и установка зависимостей через pip
4. Генерация gunicorn wrapper и systemd unit (включая `~/.cargo/bin` для rustscan)
5. `daemon-reload` + `enable` + `start`
6. Ожидание health-check (до 30 сек)
7. Финальная проверка: статус, версия, инструменты, venv

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

Health endpoint (`/health`) теперь отдаёт визуальную HTML-панель вместо голого JSON.

- **`/health`** — HTML-панель с тёмным дизайном: прогресс-бары по категориям инструментов, сетка статуса (установлен/отсутствует), системные метрики (CPU, RAM, Disk, Network)
- **`/health?json`** или **`Accept: application/json`** — JSON-ответ для API

Инструменты, которые отображаются только для информации о наличии в системе (не используются HexStrike напрямую), помечены значком `INFO`.

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

### Кэширование

- Размер кэша увеличен с 1000 до **2000** записей
- TTL кэша увеличен с 3600 до **7200** секунд (2 часа)

---

## Изменения в hexstrike_mcp.py

Изменения развёртываются автоматически скриптом `deploy.sh`.

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
   `hexstrike_mcp.py`, `scripts/`, `tests/`, `.github/`, `pytest.ini`, `.gitignore`.
5. **НЕ трогает** `hexstrike_server.py` — оставляет conflict-маркеры для
   ручного ревью (там наши правки health-панели).
6. Генерирует `MERGE_UPSTREAM_REPORT.md` со списком конфликтов и защищённых файлов.
7. **Пауза**: скрипт не делает auto-commit — ревью и коммит выполняются вручную.

После запуска разрешите маркеры (особенно в `hexstrike_server.py`), прогоните
`pytest`, закоммитьте и слейте ветку `upstream-sync` в `master`.
