# Changelog

Все заметные изменения проекта HexStrike AI (Chumikov Sec Fork) документируются здесь.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [6.5.0] — 2026-08-14

Полигон v2 (95 проверок): живые цели (SQLi/XSS/redirect/soft-404/TLS/чёрная дыра/медленная/закрытый порт), MCP-слой по stdio JSON-RPC, матрица зависаний, freeze-проба, дрейф флагов, kill-семантика, фиделити вывода, auth-инстанс. Прогоны: 90/95 → 94/95 → **95/95** после фиксов.

### Критические

- **Kill switch не убивал НИ ОДИН процесс инструмента** — `kill_switch.register` не вызывался нигде: «аварийный стоп» только блокировал новые вызовы, запущенные nmap/sqlmap продолжали работать. Теперь `EnhancedCommandExecutor` и process pool регистрируют подпроцессы у kill switch и снимают по завершении; `_signal_one` сигнализит **группу процессов** (`killpg`) — shell-обёртка `sh -c` больше не осирочивает ребёнка (pool исполняет с `setsid`).

### Развёртывание (смена модели воркеров)

- **gunicorn: sync → gthread** (`--worker-class gthread --threads 8 --graceful-timeout 320 --max-requests-jitter 200`). Два параллельных долгих скана больше не замораживают весь API (freeze-проба полигона: `/health` остаётся отзывчивым во время сканов; при sync-воркерах зависал намертво). Готовность к gthread: `HexStrikeCache` получил блокировку (мутации `OrderedDict` из нескольких потоков портили LRU/бросали `KeyError`).

### Исправлено

- **Бинарный вывод валил reader-потоки**: `text=True` со strict-декодингом — `UnicodeDecodeError` на latin-1/бинарном stdout обрывал чтение. Добавлен `errors="replace"` (curl бинарного файла больше не теряет вывод).
- **dirsearch протекал диском**: временный workdir оставался в /tmp после каждого скана. Теперь отчёт инлайнится в ответ (`report`, ≤64 КБ), workdir удаляется.
- **wpscan-фикс v6.4.9 содержал неверный флаг** — поймано флаг-смоуком полигона: в текущем wpscan опция называется `--[no-]update`; маршрут уже использует валидную форму, проверка смоука исправлена.

### Инструментарий

- `scripts/synthetic_lab.py` v2 + `scripts/mcp_client.py`: полный путь агента (MCP stdio: initialize/tools/list/tools/call, профили `HEXSTRIKE_MCP_PROFILE`, фиделити оптимизатора — трюнкация сохраняет голову/хвост/маркер), реальные находки end-to-end (sqlmap находит SQLi в SQLite-логине, dalfox — reflected XSS; негативный контроль soft-404), матрица зависаний (чёрная дыра/медленная/закрытый порт — возврат <120с), freeze-проба, флаг-смоук 15 инструментов, kill-семантика через pgrep, auth-инстанс на отдельном порту (все `/api/*` отдают 401 без ключа, включая blueprints).
- `deploy.sh`: опциональный post-deploy smoke `HEXSTRIKE_LAB_SMOKE=1` (quick-полигон из каталога исходников, не блокирует деплой).
- Тесты: 550 unit (без изменений — фиксы покрыты полигоном и предыдущими regression-тестами).

## [6.4.9] — 2026-08-14

Результаты комплексного синтетического тестирования (`scripts/synthetic_lab.py`): полигон на 127.0.0.1 (веб-сервер с директориями/страницами/«уязвимым» параметром) + батареи инъекций/guardrails/robustness. Первый прогон — 30/52, после фиксов — 52/52. Заодно полигон поймал два бага в фиксаx v6.4.8/v6.4.7.

### Критические

- **Scope-гейт был слеп для tool-роутов: вне-scope nmap реально исполнялся.** `wrap_executor` читал `parameters` только из kwargs, а `execute_command_with_recovery(tool_name, command, parameters)` везде вызывается позиционно → target=None → scope/rate-гейты пропускали всё. Теперь параметры достаются и из позиционных аргументов (`args[2]`).
- **Scope не был виден между gunicorn-воркерами** (как kill-флаг до v6.4.8): правила читались из SQLite только в `GuardrailsState.__init__` — scope, установленный через воркер A, не блокировал вызовы в воркере B. `check()` теперь обновляет правила из DB (`refresh_scope()`); `validate`-эндпоинт тоже.
- **7 инъекционных роутов (подтверждённый RCE)**: `nikto`, `dalfox`, `prowler`, `wpscan`, `autorecon`, `enum4linux-ng`, `gdb`, `radare2` (+ `dirsearch` и `sqlmap` без подтверждения) — переведены на argv-форму (`shell=False`) с валидацией target/url/путей, guardrails-диспетчеризацией и mkstemp вместо фиксированных `/tmp/*_commands.txt` (symlink-атака).

### Безопасность / корректность

- **sqlmap исполнялся в обход guardrails** (голый `execute_command`): DESTRUCTIVE-инструмент без tier-подтверждения, scope и audit. Теперь через `execute_tool_command`; параметр `target` принят как алиас к `url`.
- **Guardrails-блоки возвращали HTTP 200** (`execute_tool_command` переводит блок в dict для smart-scan): роуты теперь отдают честные 403/429/503 через `_tool_response()`.
- **`nmap-advanced aggressive=true` не требовал подтверждения** (nmap -A = DESTRUCTIVE по собственной модели проекта): добавлен params-aware promote в `classify_tool`.
- **`validate_url` пропускал мусорный netloc** (`http://h:1; echo x` валидировался по одному hostname): обращение к `.port` теперь строго валидирует порт.
- **Мусорное тело запроса → 500** (не-JSON, JSON-массив): `request.json` в роутах заменён на `_json_params()` (111 вхождений) — всегда dict, ошибки тела = 400.

### Функциональные

- **`whatweb` не имел роута вовсе** — health-панель и decision-engine на него ссылались, любой вызов 404. Добавлен `/api/tools/whatweb` (argv, guardrails).
- **dirsearch падал на каждом вызове**: Kali-сборка создаёт `reports/` в CWD (независимо от `-o`), CWD сервиса не доступен на запись. Экзекутор получил параметр `cwd`; dirsearch запускается во временном каталоге, отчёт — по возвращаемому пути `report_file`.
- **wpscan зависал на многие минуты** (проверка обновлений БД/обращения к wpscan.com при недоступной цели): добавлены `--no-update --disable-tls-checks`.
- **`--script-exclude=broadcast` — несуществующий флаг nmap** (баг в фиксе BUG-2 из v6.4.8): каждый full-скан умирал rc=255. Правильное исключение — chained AND-NOT: `--script=default,safe and not broadcast and not discovery and not external` (запятая = OR, скобки не поддерживаются, а `safe` сам содержит discovery/external скрипты вроде targets-asn — проверено на nmap 7.99).
- nmap/gobuster/nuclei: `use_recovery=False` ветка исполнялась в обход guardrails — объединено на guarded-пути.

### Известные ограничения (задокументировано)

- Rate limiter: лимиты (`GUARDRAILS_MAX_CONCURRENT=5`, `GUARDRAILS_MAX_RPS=10`) применяются **на gunicorn-воркер**; при sync-воркерах фактическая конкурентность на цель ≤ числа воркеров, concurrency-гейт практически недостижим. Shared-лимитер — кандидат на v6.5+.

### Тесты и инструментарий

- +12 unit-тестов (550 всего): позиционные параметры wrap_executor, кросс-воркерный scope, tier-promotion, мусорные тела, strict-port URL, новые nmap-выражения.
- **`scripts/synthetic_lab.py`** — воспроизводимый полигон (52 проверки): функциональные сценарии (port_scan/http_probe/directory_brute/web_vuln_scan/cloud_audit/execute_command на живых инструментах), workflow (сессии, scope, async + выживание при рестарте), инъекционная батарея, robustness. Запуск: `python3 scripts/synthetic_lab.py [--quick|--skip-restart]`.

## [6.4.8] — 2026-08-14

Фиксы по отчёту полевых испытаний v6.4.7 (CTF-уикенд на ctf.bug-makers.ru): 4 подтверждённых бага + наблюдение об audit-покрытии.

### Исправлено

- **BUG-1 (высокая): `http_probe` неработоспособен при конфликте бинарника httpx.** Роут `/api/tools/httpx` строил команду `httpx -l <target>` — синтаксис projectdiscovery/httpx (Go); в системах, где имя `httpx` перехватывает Python-клиент (Kali-пакет `python3-httpx`, `pip install httpx`), любой вызов падал с `Error: No such option: -l`, при этом health-check рапортовал `httpx: true` (проверял существование, не функциональность). Теперь:
  - `resolve_httpx_binary()` функционально различает диалекты по выводу help (`-status-code`/`-tech-detect` → PD; `<URL> [OPTIONS]` / `[OPTIONS] URL` → Python), результат кэшируется на воркер; env-override `HEXSTRIKE_HTTPX_BIN`
  - PD-вариант: argv-форма (`shell=False`, заодно закрыт injection через этот роут), цели подаются через stdin, PD-диалект флагов (`-status-code`/`-content-length`/`-web-server` вместо легаси `-sc`/`-cl`/`-server`)
  - Python-вариант: fallback — URL позиционно, ответ помечается `fallback: python-httpx`; `mode=tech-detect` возвращает 501 с подсказкой `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
  - `http_probe` MCP-глагол: `mode` теперь реально маппится на флаги сервером (раньше игнорировался)
- **BUG-2 (высокая): `port_scan(mode=full)` выполнял broadcast-скрипты вне зоны цели и зависал.** Дефолт `--script=default,discovery,safe` в `/api/tools/nmap-advanced` тянул категорию `discovery` → pre-scan скрипты (`targets-sniffer`, `broadcast-*`, `eap-info`, …) слали L2-broadcast/multicast трафик и сниффили соседей независимо от цели (утечка топологии, нарушение scope-модели), а часть падала с ошибками. Наблюдавшийся таймаут 300 c на 3 портах. Теперь:
  - дефолтный набор скриптов — `default,safe`; `--script-exclude=broadcast` добавляется всегда (в т.ч. к пользовательским наборам)
  - границы времени: `--host-timeout=2m`, `--script-timeout=30s` — один «залипший» скрипт не съедает бюджет вызова
  - роут переведён на argv-форму с allowlist-валидацией `scan_type`/`ports`/`timing`/`nse_scripts` (заодно закрыт injection через `scan_type`/`nse_scripts`)
- **BUG-3 (средняя): дедупликация оптимизатора искажала структурированные данные.** Схлопывание подряд идущих одинаковых строк молча ломало позиционно-значимый вывод (ASCII-битмапы глифов «съедались» с 19 до 5–7 строк → ложные гипотезы при анализе), маркер удаления стоял в хвосте, а не на месте. Теперь:
  - `dedup` по умолчанию **выключен** (`MCP_OPTIMIZER_DEDUP=false`; opt-in вместо opt-out)
  - при включении маркер `⟨×N identical lines⟩` вставляется ровно на месте схлопнутого блока
- **BUG-4 (средняя): отсутствие лимита на объём вывода — runaway-процесс.** Флудящий бинарник (ELF с бесконечным меню при EOF на scanf) исполнялся 1205 c и вернул 94.2 МБ stdout. Теперь:
  - потолок захвата stdout+stderr (`HEXSTRIKE_MAX_OUTPUT_BYTES`, по умолчанию 10 МБ; per-call override `max_output_bytes` в `/api/command`); при превышении процесс убивается, результат помечается `output_truncated: true` + `partial_results`
  - строки длиннее 2 КБ не пишутся в `hexstrike.log` (флуд больше не раздувает и лог)
- **Наблюдение (audit-покрытие): `/api/command` исполнялся вне трассировки guardrails.** 145 команд → 1 запись в audit (только «tiered»-вызовы). Теперь перед исполнением bare-команды выполняется guardrails-check: имя инструмента выводится из бинарника, цель — из первого IP/URL/hostname токена команды; kill switch / scope / rate / tier-гейты и audit-лог покрывают и произвольные команды. Блокировка возвращает структурированный 403/429/503.
- **Kill switch не был виден между gunicorn-воркерами** (найдено при live-верификации установки v6.4.8). Глобальный флаг читался из SQLite только в `KillSwitch.__init__` — `engage()` в одном воркере не блокировал проверки в соседних (in-memory копия устаревала). `is_engaged()` и `snapshot()` теперь считают строку DB источником истины (in-memory — fallback при недоступной DB). Подтверждено живьём: 6/6 запросов `/api/command` получают 503 после `kill-all` в другом воркере, после `reset` — 200.

### Добавлено

- `EnhancedCommandExecutor`: поддержка `stdin_data` (цели в httpx через stdin, без shell-пайпов); ключ кэша учитывает stdin (одинаковый argv с разными целями больше не схлопываются в кэше)

### Тесты

- +41 (504 → 545, все зелёные): `tests/unit/test_field_fixes.py` (nmap-advanced builder/allowlists, httpx sniff/resolver/flag-mapping, output-cap на реальном flooding-процессе, stdin, `/api/command` под guardrails — audit-строка, block по scope/tier/kill, инференс tool/target, кросс-воркерная видимость kill-флага через два KillSwitch на одной DB), обновлён `test_optimizer.py` под новый дефолт dedup и inline-маркер


## [6.4.7] — 2026-08-11

### Безопасность (critical/high из аудита)

- **Фикс command injection на всех tool-роутах.** Ранее команды собирались f-string'ом из сырого `request.json` и выполнялись через `subprocess.Popen(command, shell=True)` без какой-либо санитизации (`shlex` отсутствовал во всём проекте). Теперь:
  - `EnhancedCommandExecutor` и `_execute_command_internal` принимают argv-list (`shell=False`); легитимные флаги проходят как токены, shell-метасимволы теряют спецзначение
  - добавлены `validate_target` / `validate_url` / `_shell_split` — реджектят `;`, `$()`, backticks, CRLF, null-bytes в target/url; `additional_args` парсится через `shlex.split` и передаётся списком
  - переведены на list-form + валидацию: `/api/tools/nmap`, `/api/tools/gobuster`, `/api/tools/nuclei`, `/api/tools/sqlmap`, `/api/tools/metasploit`, `/api/tools/hydra`, `/api/tools/netexec` и 17 smart-scan helper'ов (`execute_nmap_scan` … `execute_subfinder_scan`) через новый `execute_tool_command()`
  - `netexec`: добавлен allowlist для `protocol` (smb/ssh/ldap/mssql/winrm/...)
  - `metasploit`: фиксированный путь `/tmp/mcp_msf_resource.rc` заменён на `tempfile.mkstemp` (устраняет race condition и symlink-атаку)
  - `EnhancedCommandExecutor.execute`: полный command теперь redact'ится перед логированием (`redact_credentials`), пароли/hashes больше не пишутся в `hexstrike.log`
- **Guardrails подключены к пути исполнения.** `wrap_executor` (написан в v6.4.0, но имевший 0 вызовов) теперь оборачивает `execute_command_with_recovery` — scope-validation, tier-confirmation, killswitch, rate-limiting применяются ко всем tool-диспетчерезациям. Обёртка defensive: при недоступности guardrails-DB executor fallthrough'ит (сервер продолжает работать)
- **LICENSE добавлен** (MIT) с тройной атрибуцией: m0x4m4 (оригинал) → netcuter (PL fork) → Chumikov. Без LICENSE форк технически был нераспространяем («All Rights Reserved» по умолчанию)

### Надёжность (critical из аудита — gunicorn recycle)

- **Персистентное task-хранилище (`task_store.py`).** Ранее `ProcessPool` хранил state в in-process dict'ах (`self.results`, `self.active_tasks`); gunicorn `--max-requests 1000` убивал worker → все in-flight/завершённые-но-не-опросённые задачи тихо исчезали. Теперь:
  - таблица `async_tasks` в общей SQLite (`schemas/hexstrike_sessions.sql`): `queued` → `running` → `completed`/`failed`/`lost`
  - `submit_task` / `_worker_thread` / `get_task_result` дублируют lifecycle в SQLite (best-effort, degrade-to-in-process при недоступности DB)
  - `recover()` на старте worker'а помечает leftover `running`/`queued` как `lost` — poll после recycle возвращает честный статус вместо `not_found`
  - `cleanup_old(days=7)` предотвращает unbounded growth таблицы

### Тесты

- **+48 новых тестов (456 → 504, все зелёные):**
  - `tests/unit/test_input_validation.py` (37): `validate_target` (hostname/IPv4/IPv6/CIDR/wildcard, reject shell-metachar/CRLF/null/overlong), `validate_url` (http/https/port/query, reject host-injection/CRLF/scheme-without-host), `_shell_split` (literal `;`-as-token — доказывает, что injection нейтрализован), `EnhancedCommandExecutor` argv-form (Popen получает `shell=False`), `execute_tool_command` rejects poisoned target **до** spawn'а subprocess'а
  - `tests/unit/test_task_store.py` (11): lifecycle (submit→running→completed/failed), **recover после recycle** (5 запущенных задач → 5 `lost`), idempotent recovery, cleanup-old по timestamp
- Покрытие: hexstrike_server.py 14% → 16%, общее 26% → 28%

### Совместимость

- **100% backward compat для легитимных вызовов:** все валидные target/url/flags проходят без изменений. Изменения затрагивают только значения с shell-метасимволами (которые легитимный вызов никогда не содержит)
- MCP-инструменты (`hexstrike_mcp.py`) не затронуты — они ходят через REST API, где теперь применяется валидация и guardrails
- Деплой: `deploy.sh` копирует `task_store.py` вместе с остальными py-файлами; новая таблица `async_tasks` создаётся автоматически при следующем `init_db()` (идемпотентный `CREATE TABLE IF NOT EXISTS`)

## [6.4.6] — 2026-07-07

### Изменено

- **OOM-харденинг systemd-unit'а `hexstrike.service`** (deploy.sh) — защита от инцидента, когда gunicorn-воркеры убивались OOM-киллером под нагрузкой CTF, MCP stdio рвался, а после ребута сервер не поднимался вовремя:
  - `Restart=on-failure` → `Restart=always`, `RestartSec=5` → `3`
  - `OOMPolicy=continue` — воркер, убитый OOM, пересоздаётся master'ом, юнит не падает целиком
  - `OOMScoreAdjust=-500` — понижает приоритет hexstrike как жертвы kernel OOM-киллера
  - `MemoryHigh` / `MemoryMax` — **масштабируются по RAM хоста** (30% RAM → MemoryMax, clamped [1800, 6000] MB; 65% от MAX → MemoryHigh). HexStrike троттлит/перезапускает сам себя вместо того, чтобы утянуть всю машину в OOM-ребут
  - `TimeoutStopSec=15`, `KillSignal=SIGINT` — чище shutdown
  - Override через env: `HEXSTRIKE_MEM_HIGH` / `HEXSTRIKE_MEM_MAX` (напр. `4000M`)
- **`OpenCodeStart.sh`: retry-loop проверки `/health`** вместо `sleep 2`. После ребута systemd поднимает hexstrike за ~5–25 с; старый `sleep 2` срабатывал раньше готовности → opencode фиксировал `server unavailable key=hexstrike`. Теперь лаунчер ждёт до 30×1 с (параметризуется `HEALTHSTART_RETRIES` / `HEALTHSTART_INTERVAL`) с диагностикой в stderr при провале
- `hexstrike-mcp.service` (опциональный streamable/sse): `Restart=always`, `RestartSec=3`, `OOMScoreAdjust=-500`

### Решения по зависимостям

- **MCP SDK: удержание пина `mcp>=1.27.2,<2`.** Аудит двух недавних версий протокола:
  - **2025-11-25 (финальная)** — Async Tasks, OAuth 2.1+CIMD, Elicitation, Extensions, Structured Tool Output. Поддерживается текущим SDK (резолвится `mcp==1.28.0`, что ≥ 1.23) — проект уже совместим с этой версией протокола. Breaking-changes нет.
  - **2026-07-28 (release candidate, Python SDK v2)** — крупнейший breaking-change в истории MCP: stateless-переворот (убраны `initialize`-handshake и `Mcp-Session-Id`), убраны server→client requests, JSON Schema → 2020-12, **deprecate Roots/Sampling/Logging**, ужесточения OAuth/OIDC.
  - **Вердикт: НЕ переходить на v2/2026-07-28 до stable-релиза.** Проект использует только Tools (32 инструмента) и не задействует sampling/roots/logging — именно то, что v2 ломает/deprecate. RC-статус + адаптация FastMCP/streamable-http-деплоя + отсутствие давления со стороны MCP-клиентов (OpenCode/Claude Desktop/Cursor/Cline поддерживают текущую версию) делают переход преждевременным. Пин `<2` осознанно блокирует подтягивание v2.
  - **Точечная польза 2025-11-25 для проекта:** Async Tasks (`@mcp.task()`) — кандидат на замену костылям против обрывов stdio при длительных сканах (`nmap`/`nuclei`/`sqlmap`/`metasploit`); Structured Tool Output — упрощает `hexstrike_optimizer.py`. Вынесено в roadmap, не блокирует релиз.

### Безопасность

- Корни правок — аудит логов CTF-уикенда (4–5 июля 2026): gunicorn-воркеры убивались SIGKILL в 23:06/23:11 4 июля, машина ребутилась дважды 5 июля (~4,5 ч оффлайна), MCP-сервер не переподключался, доля hexstrike-вызовов падала с 11% до 3% из-за вымывания tool-определений при компактизации контекста. Текущие правки адресуют memory/OOM/restart; поведенческая часть (compaction → prefer hexstrike_*) закрывается в ctfd-api skill (§7a).

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
