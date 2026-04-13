# Предисловие

<!-- Опишите здесь причины и цели проделанной работы -->



---

# Содержание

1. [Первый шаг](#первый-шаг)
2. [Миграция на Gunicorn](#миграция-на-gunicorn)
3. [Настройка автозапуска и OpenCode](#настройка-автозапуска-и-opencode)
4. [Изменения в hexstrike_server.py](#изменения-в-hexstrike_serverpy)
5. [Изменения в hexstrike_mcp.py](#изменения-в-hexstrike_mcpy)

---

## Первый шаг

В процессе обновления была использована библиотека `aiohttp`. Она добавлена в `requirements.txt` и, на всякий случай, лучше проверить корректность установки всех зависимостей командой:

```bash
pip3 install -r requirements.txt
```

---

## Миграция на Gunicorn

### Зачем

По умолчанию, Hexstrike 6.0 использует Flask, который использует встроенный development-сервер (`app.run()`) — он однопоточный, не имеет автоперезапуска, подвержен утечкам памяти, не переживает падения. Для фреймворка, который держит открытыми subprocess'ы Nmap/Nuclei/SQLMap по несколько минут, это неприемлемо.

### Что даёт переход на Gunicorn

- 2 worker-процесса вместо одного — параллельная обработка запросов, один долгий скан не блокирует API
- Автоперезапуск worker'ов после 1000 запросов (`--max-requests`) — защита от утечек памяти
- systemd-интеграция — автозапуск при загрузке, автоматический рестарт при падении (`Restart=on-failure`)
- Graceful reload — `kill -HUP` перезапускает worker'ов без даунтайма
- Таймаут 300с на уровне сервера — защита от зависших запросов

### Скрипт миграции

`migrate_to_gunicorn.sh` выполняет 8 шагов:

1. Проверка root-прав и наличия `hexstrike_server.py`
2. Установка Gunicorn через pip (если не установлен)
3. Автоопределение пути к `gunicorn`
4. Освобождение порта 8888 (остановка старого процесса)
5. Генерация systemd unit с корректными путями
6. `daemon-reload` + `enable` + `start`
7. Ожидание health-check (до 30 сек)
8. Финальная проверка: статус, health, workers, порт, автозапуск

При ошибке на любом этапе — выводит `systemctl status` и `journalctl` и останавливается.

#### Запуск скрипта миграции

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

## Настройка автозапуска и OpenCode

### Скрипт автозапуска

Файл `OpenCodeStart.sh` копируем в папку проекта - `/usr/share/hexstrike-ai/`

Скрипт автоматически:
1. Проверяет доступность сервера на `http://127.0.0.1:8888/health`
2. Запускает Gunicorn через systemd или вручную, если сервер не отвечает
3. Ожидает 2 секунды для инициализации и запускает MCP клиент

### Конфигурация MCP OpenCode

Необходимо внести изменения в файл конфигурации MCP OpenCode, чтобы запуск использовал наш скрипт автозапуска:

Файл: `/home/kali/.opencode/opencode.jsonc`

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

## Изменения в hexstrike_server.py

Файл `hexstrike_server.py` копируем в папку проекта - `/usr/share/hexstrike-ai/` заменяя изначальную версию

**Что было изменено:**

### Безопасность

- API аутентификация — поддержка ключей через `X-API-Key` и `Authorization: Bearer` заголовки
  - Переменные: `HEXSTRIKE_API_KEY`, `HEXSTRIKE_REQUIRE_AUTH`
- Редакция учётных данных — автоматическая маскировка паролей, токенов, API-ключей в логах (`redact_credentials()`)
- Защита от path traversal (CWE-22) — блокировка абсолютных путей, `../` последовательностей и null-байтов в `FileOperationsManager`
- Привязка к localhost — сервер слушает только `127.0.0.1` вместо `0.0.0.0`

### Кэширование

- **Размер кэша** увеличен с 1000 до **2000** записей
- **TTL кэша** увеличен с 3600 до **7200** секунд (2 часа)

---

## Изменения в hexstrike_mcp.py

Файл `hexstrike_mcp.py` копируем в папку проекта - `/usr/share/hexstrike-ai/` заменяя изначальную версию

**Что было изменено:**

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

