#!/bin/bash
#
# sync-upstream.sh — обслуживание синхронизации с upstream 0x4m4/hexstrike-ai.
#
# Роль (согласно Develop_Plan.md, F1): maintenance-режим. Upstream фактически
# заморожен, поэтому скрипт используется редко — для точечного подтягивания
# фиксов CVE/безопасности с сохранением нашего набора файлов.
#
# Что делает:
#   1. Добавляет remote `upstream` (если нет) и делает fetch.
#   2. Создаёт/сбрасывает изолированную ветку `upstream-sync` от master.
#   3. Выполняет merge upstream/master (--allow-unrelated-histories, т.к. репо
#      независимое, а не GitHub-fork).
#   4. АВТОМАТИЧЕСКИ защищает наш набор (восстанавливает из HEAD): deploy.sh,
#      VERSION, CHANGELOG.md, templates/, requirements.txt, OpenCodeStart.sh,
#      hexstrike_mcp.py, hexstrike_optimizer.py, Develop_Plan.md, scripts/,
#      tests/, .github/, pytest.ini, requirements-dev.txt.
#   5. НЕ трогает hexstrike_server.py — оставляет conflict-маркеры для ручного
#      ревью (там наши правки health-панели).
#   6. Генерирует MERGE_UPSTREAM_REPORT.md.
#   7. ПАУЗА: не делает auto-commit — ревью и коммит вручную.
#
# Запуск:  bash scripts/sync-upstream.sh
#
set -euo pipefail

UPSTREAM_URL="https://github.com/0x4m4/hexstrike-ai.git"
UPSTREAM_REMOTE="upstream"
SYNC_BRANCH="upstream-sync"
BASE_BRANCH="master"
REPORT_FILE="MERGE_UPSTREAM_REPORT.md"

# Файлы/директории, которые мы АВТО защищаем (восстанавливаем нашу версию из HEAD).
PROTECTED=(
    "README.md"
    "deploy.sh"
    "VERSION"
    "CHANGELOG.md"
    "templates"
    "requirements.txt"
    "requirements-dev.txt"
    "OpenCodeStart.sh"
    "hexstrike_mcp.py"
    "hexstrike_optimizer.py"
    "Develop_Plan.md"
    "scripts"
    "tests"
    ".github"
    "pytest.ini"
    ".gitignore"
)

# Файлы, которые НЕ трогаем авто — ручное ревью conflict-маркеров.
MANUAL_REVIEW=("hexstrike_server.py")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()   { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "Не внутри git-репозитория."
cd "$REPO_ROOT"
info "Репозиторий: $REPO_ROOT"

# Проверка чистоты рабочего дерева (кроме неотслеживаемых артефактов).
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    die "Рабочее дерево не чистое. Закоммитьте или спрячьте изменения перед sync."
fi

# ----------------------------------------------------------------------------
# 1. Remote + fetch
# ----------------------------------------------------------------------------
if git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
    info "Remote '$UPSTREAM_REMOTE' уже существует: $(git remote get-url "$UPSTREAM_REMOTE")"
else
    info "Добавляем remote '$UPSTREAM_REMOTE' -> $UPSTREAM_URL"
    git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

info "fetch из $UPSTREAM_REMOTE (может занять время)..."
if ! git fetch "$UPSTREAM_REMOTE" 2>/dev/null; then
    die "fetch не удался. Проверьте сеть/доступ к $UPSTREAM_URL"
fi
UPSTREAM_HEAD=$(git rev-parse --short "$UPSTREAM_REMOTE/master" 2>/dev/null) \
    || die "Ветка master не найдена в $UPSTREAM_REMOTE."
ok "upstream/master @ $UPSTREAM_HEAD"

# ----------------------------------------------------------------------------
# 2. Изолированная ветка
# ----------------------------------------------------------------------------
info "Создаём/сбрасываем ветку '$SYNC_BRANCH' от '$BASE_BRANCH'"
git checkout -B "$SYNC_BRANCH" "$BASE_BRANCH" >/dev/null 2>&1
ok "На ветке $SYNC_BRANCH (база: $BASE_BRANCH @ $(git rev-parse --short HEAD))"

# ----------------------------------------------------------------------------
# 3. Merge (независимые истории)
# ----------------------------------------------------------------------------
info "Сливаем $UPSTREAM_REMOTE/master (--allow-unrelated-histories)..."
# Не используем set -e для merge: конфликт — это ожидаемый возможный исход.
set +e
git merge "$UPSTREAM_REMOTE/master" \
    --allow-unrelated-histories \
    --no-ff --no-commit \
    -m "chore: sync upstream $UPSTREAM_HEAD" >/tmp/hexstrike_merge.log 2>&1
MERGE_RC=$?
set -e

if grep -qi "merge: .* - not something we can merge\|not a valid object name" /tmp/hexstrike_merge.log 2>/dev/null; then
    die "merge не удался. См. /tmp/hexstrike_merge.log"
fi

# ----------------------------------------------------------------------------
# 4. Защита нашего набора
# ----------------------------------------------------------------------------
info "Защищаем наш набор файлов (восстановление из HEAD)..."
PROTECTED_RESTORED=()
PROTECTED_SKIPPED=()
for item in "${PROTECTED[@]}"; do
    if git cat-file -e "HEAD:$item" 2>/dev/null; then
        git checkout HEAD -- "$item" 2>/dev/null && git add -- "$item" 2>/dev/null \
            && PROTECTED_RESTORED+=("$item") || PROTECTED_SKIPPED+=("$item")
    else
        PROTECTED_SKIPPED+=("$item (нет в HEAD)")
    fi
done
ok "Защищено: ${#PROTECTED_RESTORED[@]} шт."
for s in "${PROTECTED_SKIPPED[@]}"; do warn "  пропущено: $s"; done

# ----------------------------------------------------------------------------
# 5. hexstrike_server.py — ручное ревью
# ----------------------------------------------------------------------------
CONFLICTED=()
while IFS= read -r f; do
    [ -n "$f" ] && CONFLICTED+=("$f")
done < <(git diff --name-only --diff-filter=U 2>/dev/null)

info "Файлов с конфликтами (для ручного ревью): ${#CONFLICTED[@]}"
for f in "${CONFLICTED[@]}"; do warn "  CONFLICT: $f"; done
for f in "${MANUAL_REVIEW[@]}"; do
    if [ -f "$f" ] && grep -q "^<<<<<<< " "$f" 2>/dev/null; then
        warn "  ТРЕБУЕТ РУЧНОГО РЕВЬЮ: $f (наши правки health-панели)"
    fi
done

# ----------------------------------------------------------------------------
# 6. Отчёт
# ----------------------------------------------------------------------------
{
    echo "# Merge Upstream Report"
    echo "Сгенерировано: $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    echo "- **upstream:** \`$UPSTREAM_URL\`"
    echo "- **upstream/master:** $UPSTREAM_HEAD"
    echo "- **база ($BASE_BRANCH):** $(git rev-parse --short HEAD~1 2>/dev/null || git rev-parse --short HEAD)"
    echo "- **merge rc:** $MERGE_RC (0=чисто, 1=конфликты)"
    echo
    echo "## Защищено (наша версия сохранена): ${#PROTECTED_RESTORED[@]}"
    for item in "${PROTECTED_RESTORED[@]}"; do echo "- $item"; done
    echo
    echo "## Пропущено: ${#PROTECTED_SKIPPED[@]}"
    for item in "${PROTECTED_SKIPPED[@]}"; do echo "- $item"; done
    echo
    echo "## Конфликты (ручное ревью): ${#CONFLICTED[@]}"
    if [ "${#CONFLICTED[@]}" -gt 0 ]; then
        for f in "${CONFLICTED[@]}"; do echo "- **$f**"; done
        echo
        echo "> Особое внимание: \`hexstrike_server.py\` — там наши правки health-панели."
        echo "> Сравните upstream-фикс с нашими изменениями и разрешите маркеры вручную."
    else
        echo "_Нет конфликтов._"
    fi
    echo
    echo "## Следующие шаги"
    echo "1. Разрешите conflict-маркеры (особенно в \`hexstrike_server.py\`)."
    echo "2. Проверьте: \`git status\`, \`git diff --cached\`."
    echo "3. Прогоните тесты: \`pytest\`."
    echo "4. Закоммитьте: \`git commit\`."
    echo "5. Слейте в master: \`git checkout master && git merge --no-ff $SYNC_BRANCH\`."
    echo "6. Удалите ветку: \`git branch -D $SYNC_BRANCH\`."
} > "$REPORT_FILE"
ok "Отчёт: $REPORT_FILE"

# ----------------------------------------------------------------------------
# 7. Пауза
# ----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}━━━ ПАУЗА ━━━${NC}"
echo "Merge подготовлен в ветке '$SYNC_BRANCH', НО не закоммичен."
echo "Сделайте ревью conflict-маркеров и отчёта '$REPORT_FILE', затем закоммитьте вручную."
echo ""
echo -e "${CYAN}git status${NC}        — посмотреть состояние"
echo -e "${CYAN}git diff --cached${NC} — посмотреть подготовленные изменения"
echo -e "${CYAN}pytest${NC}            — прогнать тесты перед коммитом"
echo ""
[ "${#CONFLICTED[@]}" -gt 0 ] && warn "Есть неразрешённые конфликты — коммит будет невозможен до их разрешения."
