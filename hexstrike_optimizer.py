#!/usr/bin/env python3
"""
hexstrike_optimizer.py — оптимизация контекста/токенов MCP-ответов (F4, v6.3.0).

Постобработка ответов инструментов перед возвратом MCP-клиенту:
сжатие длинных выводов, дедупликация, отсечение ANSI/прогресс-мусора.
Меньше контекста -> быстрее ответы агента -> экономия токенов.

Принципы (консервативный режим по умолчанию):
- Короткие строки не трогаются (порог min_chars_to_process).
- Никаких LLM/суммаризации — только детерминированные строковые преобразования.
- Ключевые данные сохраняются: трюнкация оставляет голову + хвост вывода.
- Полностью обратимо через env MCP_OPTIMIZER_ENABLED=false.

Конфигурация через переменные окружения:
- MCP_OPTIMIZER_ENABLED   (true/false, по умолчанию true)
- MCP_OPTIMIZER_MAX_CHARS (целое, по умолчанию 20000)
- MCP_OPTIMIZER_DEDUP     (true/false, по умолчанию true)
- MCP_OPTIMIZER_STRIP_ANSI(true/false, по умолчанию true)
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict

# ANSI CSI-последовательности: \x1b[ ... буква
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# Прочие escape-последовательности (BEL, одиночные ESC-команды)
_ESCAPE_RE = re.compile(r"\x1b[@-_]|\x07")


def _as_bool(value: str, default: bool) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on") if value else default


class OutputOptimizer:
    """Детерминированный оптимизатор вывода инструментов (dict -> dict)."""

    def __init__(
        self,
        enabled: bool = True,
        max_chars: int = 20000,
        dedup: bool = True,
        strip_ansi: bool = True,
        min_chars_to_process: int = 1000,
    ):
        self.enabled = enabled
        self.max_chars = max(int(max_chars), 1)
        self.dedup = dedup
        self.strip_ansi = strip_ansi
        self.min_chars_to_process = max(int(min_chars_to_process), 1)
        # Накопленная статистика для get_stats()
        self._processed = 0
        self._truncated = 0
        self._chars_in = 0
        self._chars_out = 0

    @classmethod
    def from_env(cls) -> "OutputOptimizer":
        """Создать оптимизатор, читая конфигурацию из переменных окружения."""
        return cls(
            enabled=_as_bool(os.getenv("MCP_OPTIMIZER_ENABLED", "true"), True),
            max_chars=int(os.getenv("MCP_OPTIMIZER_MAX_CHARS", "20000")),
            dedup=_as_bool(os.getenv("MCP_OPTIMIZER_DEDUP", "true"), True),
            strip_ansi=_as_bool(os.getenv("MCP_OPTIMIZER_STRIP_ANSI", "true"), True),
        )

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------
    def optimize(self, result: Any) -> Any:
        """Оптимизировать ответ. Возвращает объект того же типа."""
        if not self.enabled or not isinstance(result, dict):
            return result

        changed = False
        chars_in = chars_out = 0
        for key, value in list(result.items()):
            if not isinstance(value, str):
                continue
            if len(value) < self.min_chars_to_process:
                continue
            original = value
            chars_in += len(original)
            optimized = self._process_text(value)
            chars_out += len(optimized)
            if optimized != original:
                result[key] = optimized
                changed = True

        self._processed += 1
        self._chars_in += chars_in
        self._chars_out += chars_out

        if changed:
            self._truncated += 1
            # Не нарушаем существующие ключи — мета-инфо в изолированном ключе.
            result["_optimizer"] = {
                "enabled": True,
                "max_chars": self.max_chars,
                "dedup": self.dedup,
                "strip_ansi": self.strip_ansi,
            }
        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "max_chars": self.max_chars,
            "dedup": self.dedup,
            "strip_ansi": self.strip_ansi,
            "responses_processed": self._processed,
            "responses_truncated": self._truncated,
            "chars_in": self._chars_in,
            "chars_out": self._chars_out,
        }

    # ------------------------------------------------------------------
    # Внутренние преобразования
    # ------------------------------------------------------------------
    def _process_text(self, text: str) -> str:
        if self.strip_ansi:
            text = _ANSI_RE.sub("", text)
            text = _ESCAPE_RE.sub("", text)

        # Схлопнуть перезаписи прогресс-баров: последовательные сегменты,
        # разделённые \r, оставляем только последний (финальное состояние).
        text = self._collapse_carriage_returns(text)

        if self.dedup:
            text = self._dedup_lines(text)

        if len(text) > self.max_chars:
            text = self._truncate(text)

        return text

    @staticmethod
    def _collapse_carriage_returns(text: str) -> str:
        if "\r" not in text:
            return text
        out_lines = []
        for line in text.split("\n"):
            # В каждой строке оставляем последний \r-сегмент (финальный вывод)
            segments = line.split("\r")
            out_lines.append(segments[-1])
        return "\n".join(out_lines)

    @staticmethod
    def _dedup_lines(text: str) -> str:
        lines = text.split("\n")
        if len(lines) <= 1:
            return text
        result = []
        prev = None
        removed = 0
        for line in lines:
            if line == prev:
                removed += 1
                continue
            result.append(line)
            prev = line
        if removed:
            # Сигнализируем о дедупликации, не искажая содержимое.
            result.append(f"\n[duplicate lines removed: {removed}]")
        return "\n".join(result)

    def _truncate(self, text: str) -> str:
        original_len = len(text)
        budget = self.max_chars
        head = int(budget * 0.6)
        tail = budget - head
        head_part = text[:head]
        tail_part = text[-tail:] if tail > 0 else ""
        removed = original_len - (head + tail)
        return (
            head_part
            + f"\n\n... [truncated {removed} chars; original {original_len}] ...\n\n"
            + tail_part
        )
