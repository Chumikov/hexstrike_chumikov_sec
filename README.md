# HexStrike AI — Chumikov Sec Fork

В своей статье https://habr.com/ru/articles/985450/ я рассмотрел интеграцию Hexstrike-AI и OpenCode в Kali Linux. С того времени вышло очень много обновлений OpenCode и всего 2 или 3 патча безопасности для HexStrike. При этом, работа указанной связки была крайне нестабильной и местами крайне медленной. Ждать обещанную 7 версию Hexstrike я не стал и решил внести несколько правок в Hexstrike и неформально получить собственную версию 6.1 данного решения.

Тут я делюсь с вами своими исправлениями и улучшениями. Планирую развивать данный репо вплоть до выхода Hexstrike 7.0.

Далее предполагается, что HexStrike и OpenCode у вас уже установлены (читайте мою статью).

---

# Содержание

1. [Установка и обновление](#установка-и-обновление)
2. [Структура проекта](#структура-проекта)
3. [Миграция на Gunicorn](#миграция-на-gunicorn)
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
sudo bash migrate_to_gunicorn.sh
```

### Обновление до новой версии

```bash
cd hexstrike_chumikov_sec
git pull
sudo bash migrate_to_gunicorn.sh
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
| `migrate_to_gunicorn.sh` | Миграция на Gunicorn + генерация systemd unit + деплой всех файлов |
| `OpenCodeStart.sh` | Автозапуск сервера + MCP-клиента для OpenCode |
| `templates/health_panel.html` | Шаблон HTML-панели мониторинга |

---

## Миграция на Gunicorn

### Зачем

По умолчанию, Hexstrike 6.0 использует Flask, который использует встроенный development-сервер (`app.run()`) — он однопоточный, не имеет автоперезапуска, подвержен утечкам памяти, не переживает падения. Для фреймворка, который держит открытыми subprocess'ы Nmap/Nuclei/SQLMap по несколько минут, это неприемлемо.

### Что даёт переход на сервер Gunicorn

- 2 worker-процесса вместо одного — параллельная обработка запросов, один долгий скан не блокирует API
- Автоперезапуск worker'ов после 1000 запросов (`--max-requests`) — защита от утечек памяти
- systemd-интеграция — автозапуск при загрузке, автоматический рестарт при падении (`Restart=on-failure`)
- Graceful reload — `kill -HUP` перезапускает worker'ов без даунтайма
- Таймаут 300с на уровне сервера — защита от зависших запросов

### Скрипт миграции

`migrate_to_gunicorn.sh` выполняет все шаги автоматически:

1. Проверка root-прав и наличия `hexstrike-ai`
2. Копирование всех файлов проекта (`hexstrike_server.py`, `hexstrike_mcp.py`, `templates/`, `VERSION`)
3. Установка Gunicorn (если не установлен)
4. Освобождение порта 8888 (остановка старого процесса)
5. Генерация systemd unit с корректными путями (включая `~/.cargo/bin` для rustscan)
6. `daemon-reload` + `enable` + `start`
7. Ожидание health-check (до 30 сек)
8. Финальная проверка: статус, health, workers, порт, автозапуск

При ошибке на любом этапе — выводит `systemctl status` и `journalctl` и останавливается.

#### Запуск

```bash
sudo bash migrate_to_gunicorn.sh
```

#### Ручная проверка после миграции

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

Изменения развёртываются автоматически скриптом `migrate_to_gunicorn.sh`.

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

Изменения развёртываются автоматически скриптом `migrate_to_gunicorn.sh`.

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
