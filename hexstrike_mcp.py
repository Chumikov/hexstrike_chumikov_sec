#!/usr/bin/env python3
"""
HexStrike AI MCP Client - Enhanced Version with Async, Caching, Batch & Rate Limiting

Enhanced Features (v6.1):
- Async HTTP requests using aiohttp
- Local MCP-level caching with TTL
- Batch operations for parallel tool execution
- Rate limiting with token bucket algorithm
- Advanced error handling with retry logic and categorization
- Request prioritization and queue management

Architecture: MCP Client for AI agent communication with HexStrike server
Framework: FastMCP integration for tool orchestration
"""

import sys
import os
import argparse
import logging
import asyncio
import hashlib
import json
import time
from typing import Dict, Any, Optional, List, Tuple, Union, Annotated
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict
from functools import wraps
import threading
import traceback

import aiohttp
import requests
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from pathlib import Path
from hexstrike_optimizer import OutputOptimizer

def get_version() -> str:
    try:
        version_file = Path(__file__).resolve().parent / "VERSION"
        return version_file.read_text().strip()
    except Exception:
        return "unknown"

class ErrorCategory(Enum):
    NETWORK = "network"
    TIMEOUT = "timeout"
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    SERVER = "server"
    CLIENT = "client"
    UNKNOWN = "unknown"

class ErrorSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class EnhancedError:
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    original_error: Optional[Exception] = None
    retry_count: int = 0
    max_retries: int = 3
    backoff_seconds: float = 1.0
    recoverable: bool = True
    recovery_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "recoverable": self.recoverable,
            "recovery_hint": self.recovery_hint
        }

class HexStrikeColors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    ELECTRIC_PURPLE = '\033[38;5;129m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    TERMINAL_GRAY = '\033[38;5;240m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLOOD_RED = '\033[38;5;124m'
    CRIMSON = '\033[38;5;160m'
    DARK_RED = '\033[38;5;88m'
    FIRE_RED = '\033[38;5;202m'
    ROSE_RED = '\033[38;5;167m'
    BURGUNDY = '\033[38;5;52m'
    SCARLET = '\033[38;5;197m'
    RUBY = '\033[38;5;161m'
    HIGHLIGHT_RED = '\033[48;5;196m\033[38;5;15m'
    HIGHLIGHT_YELLOW = '\033[48;5;226m\033[38;5;16m'
    HIGHLIGHT_GREEN = '\033[48;5;46m\033[38;5;16m'
    HIGHLIGHT_BLUE = '\033[48;5;51m\033[38;5;16m'
    HIGHLIGHT_PURPLE = '\033[48;5;129m\033[38;5;15m'
    SUCCESS = '\033[38;5;46m'
    WARNING = '\033[38;5;208m'
    ERROR = '\033[38;5;196m'
    CRITICAL = '\033[48;5;196m\033[38;5;15m\033[1m'
    INFO = '\033[38;5;51m'
    DEBUG = '\033[38;5;240m'
    VULN_CRITICAL = '\033[48;5;124m\033[38;5;15m\033[1m'
    VULN_HIGH = '\033[38;5;196m\033[1m'
    VULN_MEDIUM = '\033[38;5;208m\033[1m'
    VULN_LOW = '\033[38;5;226m'
    VULN_INFO = '\033[38;5;51m'
    TOOL_RUNNING = '\033[38;5;46m\033[5m'
    TOOL_SUCCESS = '\033[38;5;46m\033[1m'
    TOOL_FAILED = '\033[38;5;196m\033[1m'
    TOOL_TIMEOUT = '\033[38;5;208m\033[1m'
    TOOL_RECOVERY = '\033[38;5;129m\033[1m'

Colors = HexStrikeColors

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': HexStrikeColors.DEBUG,
        'INFO': HexStrikeColors.SUCCESS,
        'WARNING': HexStrikeColors.WARNING,
        'ERROR': HexStrikeColors.ERROR,
        'CRITICAL': HexStrikeColors.CRITICAL
    }
    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, HexStrikeColors.BRIGHT_WHITE)
        record.msg = f"{color}{emoji} {record.msg}{HexStrikeColors.RESET}"
        return super().format(record)

logging.basicConfig(
    level=logging.INFO,
    format="[🔥 HexStrike MCP] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)

for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike MCP] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

logger = logging.getLogger(__name__)

DEFAULT_HEXSTRIKE_SERVER = "http://127.0.0.1:8888"
DEFAULT_REQUEST_TIMEOUT = 300
MAX_RETRIES = 3

class LRUCache:
    """Thread-safe LRU Cache with TTL support for MCP-level caching."""

    def __init__(self, max_size: int = 500, default_ttl: int = 600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict = OrderedDict()
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def _generate_key(self, method: str, endpoint: str, data: Optional[Dict] = None) -> str:
        key_data = f"{method}:{endpoint}:{json.dumps(data or {}, sort_keys=True)}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Optional[Tuple[Dict[str, Any], bool]]:
        key = self._generate_key(method, endpoint, data)
        with self._lock:
            if key in self._cache:
                timestamp = self._timestamps.get(key, 0)
                if time.time() - timestamp < self.default_ttl:
                    self._cache.move_to_end(key)
                    self._hits += 1
                    return self._cache[key], True
                else:
                    del self._cache[key]
                    del self._timestamps[key]
            self._misses += 1
            return None, False

    def set(self, method: str, endpoint: str, result: Dict[str, Any], data: Optional[Dict] = None, ttl: Optional[int] = None) -> None:
        key = self._generate_key(method, endpoint, data)
        with self._lock:
            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self.max_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                del self._timestamps[oldest_key]
            self._cache[key] = result
            self._timestamps[key] = time.time() + (ttl or self.default_ttl)

    def invalidate(self, pattern: Optional[str] = None) -> int:
        with self._lock:
            if pattern is None:
                count = len(self._cache)
                self._cache.clear()
                self._timestamps.clear()
                return count
            keys_to_remove = [k for k in self._cache.keys() if pattern in k]
            for key in keys_to_remove:
                del self._cache[key]
                del self._timestamps[key]
            return len(keys_to_remove)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": f"{hit_rate:.2f}%",
                "default_ttl": self.default_ttl
            }

class RateLimiter:
    """Token bucket rate limiter with configurable limits."""

    def __init__(self, requests_per_second: float = 10.0, burst_size: int = 20):
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self._tokens = float(burst_size)
        self._last_update = time.time()
        self._lock = threading.Lock()
        self._total_requests = 0
        self._rejected_requests = 0
        self._wait_time_total = 0.0

    def _refill_tokens(self) -> None:
        now = time.time()
        elapsed = now - self._last_update
        self._tokens = min(self.burst_size, self._tokens + elapsed * self.requests_per_second)
        self._last_update = now

    def acquire(self, timeout: float = 5.0) -> Tuple[bool, float]:
        start_time = time.time()
        with self._lock:
            while True:
                self._refill_tokens()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._total_requests += 1
                    return True, 0.0
                wait_time = (1.0 - self._tokens) / self.requests_per_second
                if time.time() - start_time + wait_time > timeout:
                    self._rejected_requests += 1
                    return False, wait_time
                self._wait_time_total += wait_time
                return True, wait_time

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "requests_per_second": self.requests_per_second,
                "burst_size": self.burst_size,
                "current_tokens": self._tokens,
                "total_requests": self._total_requests,
                "rejected_requests": self._rejected_requests,
                "average_wait_time": self._wait_time_total / max(1, self._total_requests)
            }

class ErrorClassifier:
    """Classifies errors and determines recovery strategies."""

    ERROR_MAPPINGS = {
        (requests.exceptions.Timeout, aiohttp.ClientTimeout): (ErrorCategory.TIMEOUT, ErrorSeverity.HIGH),
        (requests.exceptions.ConnectionError, aiohttp.ClientConnectorError): (ErrorCategory.NETWORK, ErrorSeverity.HIGH),
        (requests.exceptions.HTTPError,): (ErrorCategory.SERVER, ErrorSeverity.MEDIUM),
    }

    HTTP_STATUS_MAPPINGS = {
        401: (ErrorCategory.AUTH, ErrorSeverity.HIGH),
        403: (ErrorCategory.AUTH, ErrorSeverity.HIGH),
        429: (ErrorCategory.RATE_LIMIT, ErrorSeverity.MEDIUM),
        500: (ErrorCategory.SERVER, ErrorSeverity.HIGH),
        502: (ErrorCategory.SERVER, ErrorSeverity.HIGH),
        503: (ErrorCategory.SERVER, ErrorSeverity.MEDIUM),
        504: (ErrorCategory.TIMEOUT, ErrorSeverity.HIGH),
    }

    @classmethod
    def classify(cls, error: Exception, http_status: Optional[int] = None) -> EnhancedError:
        if http_status and http_status in cls.HTTP_STATUS_MAPPINGS:
            category, severity = cls.HTTP_STATUS_MAPPINGS[http_status]
            return EnhancedError(
                category=category,
                severity=severity,
                message=f"HTTP {http_status} error",
                original_error=error,
                recoverable=category != ErrorCategory.AUTH,
                recovery_hint="Retry with backoff" if category in [ErrorCategory.RATE_LIMIT, ErrorCategory.TIMEOUT] else "Check credentials"
            )

        for error_types, (category, severity) in cls.ERROR_MAPPINGS.items():
            if isinstance(error, error_types):
                return EnhancedError(
                    category=category,
                    severity=severity,
                    message=str(error),
                    original_error=error,
                    recoverable=category in [ErrorCategory.NETWORK, ErrorCategory.TIMEOUT],
                    recovery_hint="Check network connectivity" if category == ErrorCategory.NETWORK else "Increase timeout"
                )

        return EnhancedError(
            category=ErrorCategory.UNKNOWN,
            severity=ErrorSeverity.MEDIUM,
            message=str(error),
            original_error=error,
            recoverable=True,
            recovery_hint="Check logs for details"
        )

class RetryStrategy:
    """Configurable retry strategy with exponential backoff."""

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 30.0,
                 exponential_base: float = 2.0, jitter: bool = True):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

    def get_delay(self, attempt: int) -> float:
        delay = min(self.base_delay * (self.exponential_base ** attempt), self.max_delay)
        if self.jitter:
            import random
            delay *= (0.5 + random.random())
        return delay

    def should_retry(self, error: EnhancedError, attempt: int) -> bool:
        if attempt >= self.max_retries:
            return False
        if error.category in [ErrorCategory.AUTH]:
            return False
        return error.recoverable

class BatchRequest:
    """Represents a batch request for parallel execution."""

    def __init__(self, requests: List[Dict[str, Any]], max_concurrent: int = 5,
                 fail_fast: bool = False, priority: int = 0):
        self.requests = requests
        self.max_concurrent = max_concurrent
        self.fail_fast = fail_fast
        self.priority = priority
        self.results: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self.completed = 0
        self.failed = 0

    def add_request(self, endpoint: str, method: str = "POST", data: Optional[Dict] = None) -> None:
        self.requests.append({
            "endpoint": endpoint,
            "method": method,
            "data": data or {}
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": len(self.requests),
            "max_concurrent": self.max_concurrent,
            "fail_fast": self.fail_fast,
            "priority": self.priority,
            "completed": self.completed,
            "failed": self.failed
        }

class AsyncHexStrikeClient:
    """Enhanced async client with caching, rate limiting, and batch operations."""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT,
                 cache_size: int = 500, cache_ttl: int = 600,
                 rate_limit_rps: float = 10.0, rate_limit_burst: int = 20):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.cache = LRUCache(max_size=cache_size, default_ttl=cache_ttl)
        self.rate_limiter = RateLimiter(requests_per_second=rate_limit_rps, burst_size=rate_limit_burst)
        self.retry_strategy = RetryStrategy()
        self._sync_session: Optional[requests.Session] = None
        self._async_session: Optional[aiohttp.ClientSession] = None
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "rate_limit_waits": 0
        }
        self.optimizer = OutputOptimizer.from_env()
        self._initialize_connection()

    def _initialize_connection(self) -> None:
        self._sync_session = requests.Session()
        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"🔗 Attempting to connect to HexStrike AI API at {self.server_url} (attempt {i+1}/{MAX_RETRIES})")
                test_response = self._sync_session.get(f"{self.server_url}/health", timeout=5)
                test_response.raise_for_status()
                health_check = test_response.json()
                connected = True
                logger.info(f"🎯 Successfully connected to HexStrike AI API Server")
                logger.info(f"🏥 Server health status: {health_check.get('status', 'unknown')}")
                logger.info(f"📊 Server version: {health_check.get('version', 'unknown')}")
                break
            except Exception as e:
                logger.warning(f"⚠️  Connection test failed: {str(e)}")
                time.sleep(2)

        if not connected:
            error_msg = f"Failed to establish connection after {MAX_RETRIES} attempts"
            logger.error(error_msg)

    async def _get_async_session(self) -> aiohttp.ClientSession:
        if self._async_session is None or self._async_session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._async_session = aiohttp.ClientSession(timeout=timeout)
        return self._async_session

    async def close(self) -> None:
        if self._async_session and not self._async_session.closed:
            await self._async_session.close()
        if self._sync_session:
            self._sync_session.close()

    def _execute_with_retry(self, request_func, *args, **kwargs) -> Dict[str, Any]:
        last_error: Optional[EnhancedError] = None

        for attempt in range(self.retry_strategy.max_retries + 1):
            try:
                acquired, wait_time = self.rate_limiter.acquire()
                if not acquired:
                    return {"error": "Rate limit exceeded", "success": False, "retry_after": wait_time}
                if wait_time > 0:
                    self._stats["rate_limit_waits"] += 1
                    time.sleep(wait_time)

                self._stats["total_requests"] += 1
                result = request_func(*args, **kwargs)
                self._stats["successful_requests"] += 1
                return self.optimizer.optimize(result)

            except Exception as e:
                last_error = ErrorClassifier.classify(e)
                last_error.retry_count = attempt

                if not self.retry_strategy.should_retry(last_error, attempt):
                    self._stats["failed_requests"] += 1
                    logger.error(f"❌ Request failed permanently: {last_error.message}")
                    return {
                        "error": last_error.message,
                        "success": False,
                        "error_details": last_error.to_dict()
                    }

                delay = self.retry_strategy.get_delay(attempt)
                logger.warning(f"⚠️  Request failed (attempt {attempt + 1}), retrying in {delay:.2f}s: {last_error.message}")
                time.sleep(delay)

        self._stats["failed_requests"] += 1
        return {
            "error": last_error.message if last_error else "Unknown error",
            "success": False,
            "error_details": last_error.to_dict() if last_error else None
        }

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None,
                 use_cache: bool = True) -> Dict[str, Any]:
        if use_cache:
            cached, hit = self.cache.get("GET", endpoint, params)
            if hit:
                self._stats["cache_hits"] += 1
                logger.debug(f"💾 Cache hit for GET {endpoint}")
                return cached

        def _request():
            url = f"{self.server_url}/{endpoint}"
            logger.debug(f"📡 GET {url} with params: {params}")
            response = self._sync_session.get(url, params=params or {}, timeout=self.timeout)
            response.raise_for_status()
            return response.json()

        result = self._execute_with_retry(_request)
        if use_cache and result.get("success", True) and "error" not in result:
            self.cache.set("GET", endpoint, result, params)
        return result

    def safe_post(self, endpoint: str, json_data: Dict[str, Any],
                  use_cache: bool = False, cache_ttl: Optional[int] = None) -> Dict[str, Any]:
        if use_cache:
            cached, hit = self.cache.get("POST", endpoint, json_data)
            if hit:
                self._stats["cache_hits"] += 1
                logger.debug(f"💾 Cache hit for POST {endpoint}")
                return cached

        def _request():
            url = f"{self.server_url}/{endpoint}"
            logger.debug(f"📡 POST {url} with data: {json_data}")
            response = self._sync_session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()

        result = self._execute_with_retry(_request)
        if use_cache and result.get("success", True) and "error" not in result:
            self.cache.set("POST", endpoint, result, json_data, ttl=cache_ttl)
        return result

    async def async_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None,
                        use_cache: bool = True) -> Dict[str, Any]:
        if use_cache:
            cached, hit = self.cache.get("GET", endpoint, params)
            if hit:
                self._stats["cache_hits"] += 1
                return cached

        acquired, wait_time = self.rate_limiter.acquire()
        if not acquired:
            return {"error": "Rate limit exceeded", "success": False}

        if wait_time > 0:
            self._stats["rate_limit_waits"] += 1
            await asyncio.sleep(wait_time)

        session = await self._get_async_session()
        url = f"{self.server_url}/{endpoint}"

        for attempt in range(self.retry_strategy.max_retries + 1):
            try:
                self._stats["total_requests"] += 1
                async with session.get(url, params=params or {}) as response:
                    response.raise_for_status()
                    result = await response.json()
                    self._stats["successful_requests"] += 1
                    if use_cache:
                        self.cache.set("GET", endpoint, result, params)
                    return result
            except Exception as e:
                error = ErrorClassifier.classify(e)
                if not self.retry_strategy.should_retry(error, attempt):
                    self._stats["failed_requests"] += 1
                    return {"error": str(e), "success": False, "error_details": error.to_dict()}
                delay = self.retry_strategy.get_delay(attempt)
                await asyncio.sleep(delay)

        return {"error": "Max retries exceeded", "success": False}

    async def async_post(self, endpoint: str, json_data: Dict[str, Any],
                         use_cache: bool = False) -> Dict[str, Any]:
        if use_cache:
            cached, hit = self.cache.get("POST", endpoint, json_data)
            if hit:
                self._stats["cache_hits"] += 1
                return cached

        acquired, wait_time = self.rate_limiter.acquire()
        if not acquired:
            return {"error": "Rate limit exceeded", "success": False}

        if wait_time > 0:
            self._stats["rate_limit_waits"] += 1
            await asyncio.sleep(wait_time)

        session = await self._get_async_session()
        url = f"{self.server_url}/{endpoint}"

        for attempt in range(self.retry_strategy.max_retries + 1):
            try:
                self._stats["total_requests"] += 1
                async with session.post(url, json=json_data) as response:
                    response.raise_for_status()
                    result = await response.json()
                    self._stats["successful_requests"] += 1
                    if use_cache:
                        self.cache.set("POST", endpoint, result, json_data)
                    return result
            except Exception as e:
                error = ErrorClassifier.classify(e)
                if not self.retry_strategy.should_retry(error, attempt):
                    self._stats["failed_requests"] += 1
                    return {"error": str(e), "success": False, "error_details": error.to_dict()}
                delay = self.retry_strategy.get_delay(attempt)
                await asyncio.sleep(delay)

        return {"error": "Max retries exceeded", "success": False}

    async def execute_batch(self, batch: BatchRequest) -> Dict[str, Any]:
        semaphore = asyncio.Semaphore(batch.max_concurrent)

        async def execute_single(request: Dict[str, Any]) -> Dict[str, Any]:
            async with semaphore:
                try:
                    if request["method"].upper() == "GET":
                        result = await self.async_get(request["endpoint"], request.get("data"))
                    else:
                        result = await self.async_post(request["endpoint"], request.get("data", {}))
                    batch.completed += 1
                    batch.results.append(result)
                    return result
                except Exception as e:
                    batch.failed += 1
                    error_info = {"error": str(e), "request": request, "success": False}
                    batch.errors.append(error_info)
                    if batch.fail_fast:
                        raise
                    return error_info

        tasks = [execute_single(req) for req in batch.requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "success": batch.failed == 0,
            "total_requests": len(batch.requests),
            "completed": batch.completed,
            "failed": batch.failed,
            "results": batch.results,
            "errors": batch.errors
        }

    def execute_batch_sync(self, batch: BatchRequest) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, self.execute_batch(batch))
                    return future.result()
            else:
                return loop.run_until_complete(self.execute_batch(batch))
        except RuntimeError:
            return asyncio.run(self.execute_batch(batch))

    def check_health(self) -> Dict[str, Any]:
        return self.safe_get("health")

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command, "use_cache": use_cache})

    def get_stats(self) -> Dict[str, Any]:
        return {
            "requests": self._stats,
            "cache": self.cache.get_stats(),
            "rate_limiter": self.rate_limiter.get_stats()
        }

    def clear_cache(self, pattern: Optional[str] = None) -> Dict[str, Any]:
        invalidated = self.cache.invalidate(pattern)
        return {"success": True, "invalidated_entries": invalidated}

HexStrikeClient = AsyncHexStrikeClient

def setup_mcp_server(hexstrike_client: HexStrikeClient) -> FastMCP:
    mcp = FastMCP("hexstrike-ai-mcp")

    @mcp.tool()
    def batch_execute(
        requests: Annotated[str, Field(description='JSON string: list of requests, each {"endpoint": "...", "method": "POST", "data": {...}}')],
        max_concurrent: Annotated[int, Field(description="Maximum number of concurrent requests")] = 5,
        fail_fast: Annotated[bool, Field(description="Stop on first error if True")] = False,
    ) -> Dict[str, Any]:
        """
        Execute multiple API requests in parallel with batch optimization.

        Args:
            requests: JSON string containing list of requests. Each request: {"endpoint": "...", "method": "POST", "data": {...}}
            max_concurrent: Maximum number of concurrent requests (default: 5)
            fail_fast: Stop on first error if True (default: False)

        Returns:
            Batch execution results with success/failure counts and individual results
        """
        try:
            request_list = json.loads(requests) if isinstance(requests, str) else requests
            batch = BatchRequest(requests=request_list, max_concurrent=max_concurrent, fail_fast=fail_fast)
            result = hexstrike_client.execute_batch_sync(batch)
            logger.info(f"📦 Batch executed: {result['completed']}/{result['total_requests']} successful")
            return result
        except Exception as e:
            logger.error(f"❌ Batch execution failed: {str(e)}")
            return {"error": str(e), "success": False}

    @mcp.tool()
    def get_mcp_stats() -> Dict[str, Any]:
        """
        Get MCP client statistics including cache, rate limiter, and request metrics.

        Returns:
            Statistics for cache, rate limiter, and request counts
        """
        stats = hexstrike_client.get_stats()
        logger.info("📊 Retrieved MCP client statistics")
        return stats

    @mcp.tool()
    def clear_mcp_cache(
        pattern: Annotated[str, Field(description="Optional pattern to match cache keys (empty = clear all)")] = "",
    ) -> Dict[str, Any]:
        """
        Clear MCP-level cache. Optionally filter by pattern.

        Args:
            pattern: Optional pattern to match cache keys (empty = clear all)

        Returns:
            Number of cache entries invalidated
        """
        result = hexstrike_client.clear_cache(pattern if pattern else None)
        logger.info(f"🧹 Cleared MCP cache: {result['invalidated_entries']} entries")
        return result

    @mcp.tool()
    def nmap_scan(
        target: Annotated[str, Field(description="The IP address or hostname to scan")],
        scan_type: Annotated[str, Field(description="Scan type (e.g. -sV version detection, -sC scripts)")] = "-sV",
        ports: Annotated[str, Field(description="Comma-separated list of ports or port ranges")] = "",
        additional_args: Annotated[str, Field(description="Additional Nmap arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute an enhanced Nmap scan against a target with real-time logging.

        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection, -sC for scripts)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments

        Returns:
            Scan results with enhanced telemetry
        """
        data = {"target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"{HexStrikeColors.FIRE_RED}🔍 Initiating Nmap scan: {target}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/nmap", data, use_cache=False)
        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Nmap scan completed for {target}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Nmap scan failed for {target}{HexStrikeColors.RESET}")
        return result

    @mcp.tool()
    def gobuster_scan(
        url: Annotated[str, Field(description="The target URL")],
        mode: Annotated[str, Field(description="Scan mode (dir, dns, fuzz, vhost)")] = "dir",
        wordlist: Annotated[str, Field(description="Path to wordlist file")] = "/usr/share/wordlists/dirb/common.txt",
        additional_args: Annotated[str, Field(description="Additional Gobuster arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.

        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments

        Returns:
            Scan results with enhanced telemetry
        """
        data = {"url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"{HexStrikeColors.CRIMSON}📁 Starting Gobuster {mode} scan: {url}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/gobuster", data)
        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Gobuster scan completed for {url}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Gobuster scan failed for {url}{HexStrikeColors.RESET}")
        return result

    @mcp.tool()
    def nuclei_scan(
        target: Annotated[str, Field(description="The target URL or IP")],
        severity: Annotated[str, Field(description="Filter by severity (critical,high,medium,low,info)")] = "",
        tags: Annotated[str, Field(description="Filter by tags (e.g. cve,rce,lfi)")] = "",
        template: Annotated[str, Field(description="Custom template path")] = "",
        additional_args: Annotated[str, Field(description="Additional Nuclei arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner with enhanced logging.

        Args:
            target: The target URL or IP
            severity: Filter by severity (critical,high,medium,low,info)
            tags: Filter by tags (e.g. cve,rce,lfi)
            template: Custom template path
            additional_args: Additional Nuclei arguments

        Returns:
            Scan results with discovered vulnerabilities
        """
        data = {"target": target, "severity": severity, "tags": tags, "template": template, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"{HexStrikeColors.BLOOD_RED}🔬 Starting Nuclei scan: {target}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/nuclei", data)
        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Nuclei scan completed for {target}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Nuclei scan failed for {target}{HexStrikeColors.RESET}")
        return result

    @mcp.tool()
    def prowler_scan(
        provider: Annotated[str, Field(description="Cloud provider (aws, azure, gcp)")] = "aws",
        profile: Annotated[str, Field(description="AWS/Cloud profile to use")] = "default",
        region: Annotated[str, Field(description="Specific region to scan")] = "",
        checks: Annotated[str, Field(description="Specific checks to run")] = "",
        output_dir: Annotated[str, Field(description="Directory to save results")] = "/tmp/prowler_output",
        output_format: Annotated[str, Field(description="Output format (json, csv, html)")] = "json",
        additional_args: Annotated[str, Field(description="Additional Prowler arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Prowler for comprehensive cloud security assessment.

        Args:
            provider: Cloud provider (aws, azure, gcp)
            profile: AWS profile to use
            region: Specific region to scan
            checks: Specific checks to run
            output_dir: Directory to save results
            output_format: Output format (json, csv, html)
            additional_args: Additional Prowler arguments

        Returns:
            Cloud security assessment results
        """
        data = {"provider": provider, "profile": profile, "region": region, "checks": checks,
                "output_dir": output_dir, "output_format": output_format, "additional_args": additional_args}
        logger.info(f"☁️  Starting Prowler {provider} security assessment")
        result = hexstrike_client.safe_post("api/tools/prowler", data)
        if result.get("success"):
            logger.info(f"✅ Prowler assessment completed")
        else:
            logger.error(f"❌ Prowler assessment failed")
        return result

    @mcp.tool()
    def trivy_scan(
        scan_type: Annotated[str, Field(description="Type of scan (image, fs, repo, config)")] = "image",
        target: Annotated[str, Field(description="Target to scan (image name, directory, repository)")] = "",
        output_format: Annotated[str, Field(description="Output format (json, table, sarif)")] = "json",
        severity: Annotated[str, Field(description="Severity filter (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)")] = "",
        output_file: Annotated[str, Field(description="File to save results")] = "",
        additional_args: Annotated[str, Field(description="Additional Trivy arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Trivy for container and filesystem vulnerability scanning.

        Args:
            scan_type: Type of scan (image, fs, repo, config)
            target: Target to scan (image name, directory, repository)
            output_format: Output format (json, table, sarif)
            severity: Severity filter (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)
            output_file: File to save results
            additional_args: Additional Trivy arguments

        Returns:
            Vulnerability scan results
        """
        data = {"scan_type": scan_type, "target": target, "output_format": output_format,
                "severity": severity, "output_file": output_file, "additional_args": additional_args}
        logger.info(f"🔍 Starting Trivy {scan_type} scan: {target}")
        result = hexstrike_client.safe_post("api/tools/trivy", data)
        if result.get("success"):
            logger.info(f"✅ Trivy scan completed for {target}")
        else:
            logger.error(f"❌ Trivy scan failed for {target}")
        return result

    @mcp.tool()
    def nikto_scan(
        target: Annotated[str, Field(description="The target URL or IP")],
        additional_args: Annotated[str, Field(description="Additional Nikto arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Nikto web vulnerability scanner.

        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments

        Returns:
            Scan results with discovered vulnerabilities
        """
        data = {"target": target, "additional_args": additional_args}
        logger.info(f"🔬 Starting Nikto scan: {target}")
        result = hexstrike_client.safe_post("api/tools/nikto", data)
        if result.get("success"):
            logger.info(f"✅ Nikto scan completed for {target}")
        else:
            logger.error(f"❌ Nikto scan failed for {target}")
        return result

    @mcp.tool()
    def sqlmap_scan(
        url: Annotated[str, Field(description="The target URL")],
        data: Annotated[str, Field(description="POST data for testing")] = "",
        additional_args: Annotated[str, Field(description="Additional SQLMap arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute SQLMap for SQL injection testing.

        Args:
            url: The target URL
            data: POST data for testing
            additional_args: Additional SQLMap arguments

        Returns:
            SQL injection test results
        """
        data_payload = {"url": url, "data": data, "additional_args": additional_args}
        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = hexstrike_client.safe_post("api/tools/sqlmap", data_payload)
        if result.get("success"):
            logger.info(f"✅ SQLMap scan completed for {url}")
        else:
            logger.error(f"❌ SQLMap scan failed for {url}")
        return result

    @mcp.tool()
    def hydra_attack(
        target: Annotated[str, Field(description="The target IP or hostname")],
        service: Annotated[str, Field(description="The service to attack (ssh, ftp, http, etc.)")],
        username: Annotated[str, Field(description="Single username to test")] = "",
        username_file: Annotated[str, Field(description="File containing usernames")] = "",
        password: Annotated[str, Field(description="Single password to test")] = "",
        password_file: Annotated[str, Field(description="File containing passwords")] = "",
        additional_args: Annotated[str, Field(description="Additional Hydra arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Hydra for password brute forcing.

        Args:
            target: The target IP or hostname
            service: The service to attack (ssh, ftp, http, etc.)
            username: Single username to test
            username_file: File containing usernames
            password: Single password to test
            password_file: File containing passwords
            additional_args: Additional Hydra arguments

        Returns:
            Brute force attack results
        """
        data = {"target": target, "service": service, "username": username, "username_file": username_file,
                "password": password, "password_file": password_file, "additional_args": additional_args}
        logger.info(f"🔑 Starting Hydra attack: {target}:{service}")
        result = hexstrike_client.safe_post("api/tools/hydra", data)
        if result.get("success"):
            logger.info(f"✅ Hydra attack completed for {target}")
        else:
            logger.error(f"❌ Hydra attack failed for {target}")
        return result

    @mcp.tool()
    def ffuf_scan(
        url: Annotated[str, Field(description="The target URL")],
        wordlist: Annotated[str, Field(description="Wordlist file to use")] = "/usr/share/wordlists/dirb/common.txt",
        mode: Annotated[str, Field(description="Fuzzing mode (directory, vhost, parameter)")] = "directory",
        match_codes: Annotated[str, Field(description="HTTP status codes to match")] = "200,204,301,302,307,401,403",
        additional_args: Annotated[str, Field(description="Additional FFuf arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute FFuf for web fuzzing.

        Args:
            url: The target URL
            wordlist: Wordlist file to use
            mode: Fuzzing mode (directory, vhost, parameter)
            match_codes: HTTP status codes to match
            additional_args: Additional FFuf arguments

        Returns:
            Web fuzzing results
        """
        data = {"url": url, "wordlist": wordlist, "mode": mode, "match_codes": match_codes, "additional_args": additional_args}
        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
        result = hexstrike_client.safe_post("api/tools/ffuf", data)
        if result.get("success"):
            logger.info(f"✅ FFuf fuzzing completed for {url}")
        else:
            logger.error(f"❌ FFuf fuzzing failed for {url}")
        return result

    @mcp.tool()
    def amass_scan(
        domain: Annotated[str, Field(description="The target domain")],
        mode: Annotated[str, Field(description="Amass mode (enum, intel, viz)")] = "enum",
        additional_args: Annotated[str, Field(description="Additional Amass arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Amass for subdomain enumeration.

        Args:
            domain: The target domain
            mode: Amass mode (enum, intel, viz)
            additional_args: Additional Amass arguments

        Returns:
            Subdomain enumeration results
        """
        data = {"domain": domain, "mode": mode, "additional_args": additional_args}
        logger.info(f"🔍 Starting Amass {mode}: {domain}")
        result = hexstrike_client.safe_post("api/tools/amass", data)
        if result.get("success"):
            logger.info(f"✅ Amass completed for {domain}")
        else:
            logger.error(f"❌ Amass failed for {domain}")
        return result

    @mcp.tool()
    def subfinder_scan(
        domain: Annotated[str, Field(description="The target domain")],
        silent: Annotated[bool, Field(description="Run in silent mode")] = True,
        all_sources: Annotated[bool, Field(description="Use all sources")] = False,
        additional_args: Annotated[str, Field(description="Additional Subfinder arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Subfinder for passive subdomain enumeration.

        Args:
            domain: The target domain
            silent: Run in silent mode
            all_sources: Use all sources
            additional_args: Additional Subfinder arguments

        Returns:
            Passive subdomain enumeration results
        """
        data = {"domain": domain, "silent": silent, "all_sources": all_sources, "additional_args": additional_args}
        logger.info(f"🔍 Starting Subfinder: {domain}")
        result = hexstrike_client.safe_post("api/tools/subfinder", data)
        if result.get("success"):
            logger.info(f"✅ Subfinder completed for {domain}")
        else:
            logger.error(f"❌ Subfinder failed for {domain}")
        return result

    @mcp.tool()
    def httpx_probe(
        target: Annotated[str, Field(description="Target file or single URL")],
        probe: Annotated[bool, Field(description="Enable probing")] = True,
        tech_detect: Annotated[bool, Field(description="Enable technology detection")] = False,
        status_code: Annotated[bool, Field(description="Show status codes")] = False,
        content_length: Annotated[bool, Field(description="Show content length")] = False,
        title: Annotated[bool, Field(description="Show page titles")] = False,
        web_server: Annotated[bool, Field(description="Show web server")] = False,
        threads: Annotated[int, Field(description="Number of threads")] = 50,
        additional_args: Annotated[str, Field(description="Additional httpx arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute httpx for fast HTTP probing and technology detection.

        Args:
            target: Target file or single URL
            probe: Enable probing
            tech_detect: Enable technology detection
            status_code: Show status codes
            content_length: Show content length
            title: Show page titles
            web_server: Show web server
            threads: Number of threads
            additional_args: Additional httpx arguments

        Returns:
            Fast HTTP probing results
        """
        data = {"target": target, "probe": probe, "tech_detect": tech_detect, "status_code": status_code,
                "content_length": content_length, "title": title, "web_server": web_server,
                "threads": threads, "additional_args": additional_args}
        logger.info(f"🌍 Starting httpx probe: {target}")
        result = hexstrike_client.safe_post("api/tools/httpx", data)
        if result.get("success"):
            logger.info(f"✅ httpx probe completed for {target}")
        else:
            logger.error(f"❌ httpx probe failed for {target}")
        return result

    @mcp.tool()
    def dirsearch_scan(
        url: Annotated[str, Field(description="The target URL")],
        extensions: Annotated[str, Field(description="File extensions to search for")] = "php,html,js,txt,xml,json",
        wordlist: Annotated[str, Field(description="Wordlist file to use")] = "/usr/share/wordlists/dirsearch/common.txt",
        threads: Annotated[int, Field(description="Number of threads to use")] = 30,
        recursive: Annotated[bool, Field(description="Enable recursive scanning")] = False,
        additional_args: Annotated[str, Field(description="Additional Dirsearch arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Dirsearch for advanced directory and file discovery.

        Args:
            url: The target URL
            extensions: File extensions to search for
            wordlist: Wordlist file to use
            threads: Number of threads to use
            recursive: Enable recursive scanning
            additional_args: Additional Dirsearch arguments

        Returns:
            Directory discovery results
        """
        data = {"url": url, "extensions": extensions, "wordlist": wordlist,
                "threads": threads, "recursive": recursive, "additional_args": additional_args}
        logger.info(f"📁 Starting Dirsearch scan: {url}")
        result = hexstrike_client.safe_post("api/tools/dirsearch", data)
        if result.get("success"):
            logger.info(f"✅ Dirsearch scan completed for {url}")
        else:
            logger.error(f"❌ Dirsearch scan failed for {url}")
        return result

    @mcp.tool()
    def katana_crawl(
        url: Annotated[str, Field(description="The target URL to crawl")],
        depth: Annotated[int, Field(description="Crawling depth")] = 3,
        js_crawl: Annotated[bool, Field(description="Enable JavaScript crawling")] = True,
        form_extraction: Annotated[bool, Field(description="Enable form extraction")] = True,
        output_format: Annotated[str, Field(description="Output format (json, txt)")] = "json",
        additional_args: Annotated[str, Field(description="Additional Katana arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Katana for next-generation crawling and spidering.

        Args:
            url: The target URL to crawl
            depth: Crawling depth
            js_crawl: Enable JavaScript crawling
            form_extraction: Enable form extraction
            output_format: Output format (json, txt)
            additional_args: Additional Katana arguments

        Returns:
            Web crawling results with endpoints and forms
        """
        data = {"url": url, "depth": depth, "js_crawl": js_crawl,
                "form_extraction": form_extraction, "output_format": output_format,
                "additional_args": additional_args}
        logger.info(f"⚔️  Starting Katana crawl: {url}")
        result = hexstrike_client.safe_post("api/tools/katana", data)
        if result.get("success"):
            logger.info(f"✅ Katana crawl completed for {url}")
        else:
            logger.error(f"❌ Katana crawl failed for {url}")
        return result

    @mcp.tool()
    def nmap_advanced_scan(
        target: Annotated[str, Field(description="The target IP address or hostname")],
        scan_type: Annotated[str, Field(description="Nmap scan type (e.g. -sS, -sT, -sU)")] = "-sS",
        ports: Annotated[str, Field(description="Specific ports to scan")] = "",
        timing: Annotated[str, Field(description="Timing template (T0-T5)")] = "T4",
        nse_scripts: Annotated[str, Field(description="Custom NSE scripts to run")] = "",
        os_detection: Annotated[bool, Field(description="Enable OS detection")] = False,
        version_detection: Annotated[bool, Field(description="Enable version detection")] = False,
        aggressive: Annotated[bool, Field(description="Enable aggressive scanning")] = False,
        stealth: Annotated[bool, Field(description="Enable stealth mode")] = False,
        additional_args: Annotated[str, Field(description="Additional Nmap arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute advanced Nmap scans with custom NSE scripts and optimized timing.

        Args:
            target: The target IP address or hostname
            scan_type: Nmap scan type (e.g., -sS, -sT, -sU)
            ports: Specific ports to scan
            timing: Timing template (T0-T5)
            nse_scripts: Custom NSE scripts to run
            os_detection: Enable OS detection
            version_detection: Enable version detection
            aggressive: Enable aggressive scanning
            stealth: Enable stealth mode
            additional_args: Additional Nmap arguments

        Returns:
            Advanced Nmap scanning results
        """
        data = {"target": target, "scan_type": scan_type, "ports": ports, "timing": timing,
                "nse_scripts": nse_scripts, "os_detection": os_detection,
                "version_detection": version_detection, "aggressive": aggressive,
                "stealth": stealth, "additional_args": additional_args}
        logger.info(f"🔍 Starting Advanced Nmap: {target}")
        result = hexstrike_client.safe_post("api/tools/nmap-advanced", data)
        if result.get("success"):
            logger.info(f"✅ Advanced Nmap completed for {target}")
        else:
            logger.error(f"❌ Advanced Nmap failed for {target}")
        return result

    @mcp.tool()
    def rustscan_fast_scan(
        target: Annotated[str, Field(description="The target IP address or hostname")],
        ports: Annotated[str, Field(description='Specific ports to scan (e.g. "22,80,443")')] = "",
        ulimit: Annotated[int, Field(description="File descriptor limit")] = 5000,
        batch_size: Annotated[int, Field(description="Batch size for scanning")] = 4500,
        timeout: Annotated[int, Field(description="Timeout in milliseconds")] = 1500,
        scripts: Annotated[bool, Field(description="Run Nmap scripts on discovered ports")] = False,
        additional_args: Annotated[str, Field(description="Additional Rustscan arguments")] = "",
    ) -> Dict[str, Any]:
        """
        Execute Rustscan for ultra-fast port scanning.

        Args:
            target: The target IP address or hostname
            ports: Specific ports to scan (e.g., "22,80,443")
            ulimit: File descriptor limit
            batch_size: Batch size for scanning
            timeout: Timeout in milliseconds
            scripts: Run Nmap scripts on discovered ports
            additional_args: Additional Rustscan arguments

        Returns:
            Ultra-fast port scanning results
        """
        data = {"target": target, "ports": ports, "ulimit": ulimit, "batch_size": batch_size,
                "timeout": timeout, "scripts": scripts, "additional_args": additional_args}
        logger.info(f"⚡ Starting Rustscan: {target}")
        result = hexstrike_client.safe_post("api/tools/rustscan", data)
        if result.get("success"):
            logger.info(f"✅ Rustscan completed for {target}")
        else:
            logger.error(f"❌ Rustscan failed for {target}")
        return result

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the HexStrike AI server.

        Returns:
            Server health information with tool availability
        """
        logger.info("🏥 Checking HexStrike AI server health")
        result = hexstrike_client.check_health()
        if result.get("status") == "healthy":
            logger.info(f"✅ Server is healthy - {result.get('total_tools_available', 0)} tools available")
        else:
            logger.warning(f"⚠️  Server health check returned: {result.get('status', 'unknown')}")
        return result

    @mcp.tool()
    def execute_command(
        command: Annotated[str, Field(description="The command to execute")],
        use_cache: Annotated[bool, Field(description="Whether to use caching")] = True,
    ) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the HexStrike AI server.

        Args:
            command: The command to execute
            use_cache: Whether to use caching

        Returns:
            Command execution results
        """
        try:
            logger.info(f"⚡ Executing command: {command}")
            result = hexstrike_client.execute_command(command, use_cache)
            if "error" in result:
                logger.error(f"❌ Command failed: {result['error']}")
                return {"success": False, "error": result["error"], "stdout": "", "stderr": f"Error: {result['error']}"}
            if result.get("success"):
                execution_time = result.get("execution_time", 0)
                logger.info(f"✅ Command completed in {execution_time:.2f}s")
            return result
        except Exception as e:
            logger.error(f"💥 Error executing command: {str(e)}")
            return {"success": False, "error": str(e), "stdout": "", "stderr": f"Error: {str(e)}"}

    @mcp.tool()
    def intelligent_smart_scan(
        target: Annotated[str, Field(description="Target to scan")],
        objective: Annotated[str, Field(description='Scanning objective: "comprehensive", "quick", or "stealth"')] = "comprehensive",
        max_tools: Annotated[int, Field(description="Maximum number of tools to use")] = 5,
    ) -> Dict[str, Any]:
        """
        Execute an intelligent scan using AI-driven tool selection.

        Args:
            target: Target to scan
            objective: Scanning objective - "comprehensive", "quick", or "stealth"
            max_tools: Maximum number of tools to use

        Returns:
            Results from AI-optimized scanning
        """
        logger.info(f"{HexStrikeColors.FIRE_RED}🚀 Starting intelligent smart scan for {target}{HexStrikeColors.RESET}")
        data = {"target": target, "objective": objective, "max_tools": max_tools}
        result = hexstrike_client.safe_post("api/intelligence/smart-scan", data)
        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Intelligent scan completed for {target}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Intelligent scan failed for {target}{HexStrikeColors.RESET}")
        return result

    @mcp.tool()
    def analyze_target_intelligence(
        target: Annotated[str, Field(description="Target URL, IP address, or domain to analyze")],
    ) -> Dict[str, Any]:
        """
        Analyze target using AI-powered intelligence to create comprehensive profile.

        Args:
            target: Target URL, IP address, or domain to analyze

        Returns:
            Comprehensive target profile with risk assessment
        """
        logger.info(f"🧠 Analyzing target intelligence for: {target}")
        data = {"target": target}
        result = hexstrike_client.safe_post("api/intelligence/analyze-target", data)
        if result.get("success"):
            profile = result.get("target_profile", {})
            logger.info(f"✅ Target analysis completed - Type: {profile.get('target_type')}, Risk: {profile.get('risk_level')}")
        else:
            logger.error(f"❌ Target analysis failed for {target}")
        return result

    @mcp.tool()
    def create_file(
        filename: Annotated[str, Field(description="Name of the file to create")],
        content: Annotated[str, Field(description="Content to write to the file")],
        binary: Annotated[bool, Field(description="Whether the content is binary data")] = False,
    ) -> Dict[str, Any]:
        """
        Create a file with specified content on the HexStrike server.

        Args:
            filename: Name of the file to create
            content: Content to write to the file
            binary: Whether the content is binary data

        Returns:
            File creation results
        """
        data = {"filename": filename, "content": content, "binary": binary}
        logger.info(f"📄 Creating file: {filename}")
        result = hexstrike_client.safe_post("api/files/create", data)
        if result.get("success"):
            logger.info(f"✅ File created: {filename}")
        else:
            logger.error(f"❌ Failed to create file: {filename}")
        return result

    @mcp.tool()
    def list_files(
        directory: Annotated[str, Field(description="Directory to list (relative to server's base directory)")] = ".",
    ) -> Dict[str, Any]:
        """
        List files in a directory on the HexStrike server.

        Args:
            directory: Directory to list (relative to server's base directory)

        Returns:
            Directory listing results
        """
        logger.info(f"📂 Listing files in directory: {directory}")
        result = hexstrike_client.safe_get("api/files/list", {"directory": directory})
        if result.get("success"):
            file_count = len(result.get("files", []))
            logger.info(f"✅ Listed {file_count} files in {directory}")
        else:
            logger.error(f"❌ Failed to list files in {directory}")
        return result

    return mcp

def parse_args():
    parser = argparse.ArgumentParser(description="Run the HexStrike AI MCP Client (Enhanced v7.0)")
    parser.add_argument("--server", type=str, default=DEFAULT_HEXSTRIKE_SERVER,
                        help=f"HexStrike AI API server URL (default: {DEFAULT_HEXSTRIKE_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                        help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--cache-size", type=int, default=500,
                        help="MCP cache size (default: 500)")
    parser.add_argument("--cache-ttl", type=int, default=600,
                        help="MCP cache TTL in seconds (default: 600)")
    parser.add_argument("--rate-limit", type=float, default=10.0,
                        help="Rate limit requests per second (default: 10.0)")
    parser.add_argument("--rate-burst", type=int, default=20,
                        help="Rate limit burst size (default: 20)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    args = parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")

    logger.info(f"🚀 Starting HexStrike AI MCP Client v7.0 (Enhanced)")
    logger.info(f"🔗 Connecting to: {args.server}")
    logger.info(f"📊 Cache: size={args.cache_size}, TTL={args.cache_ttl}s")
    logger.info(f"⚡ Rate limit: {args.rate_limit} req/s, burst={args.rate_burst}")

    try:
        hexstrike_client = AsyncHexStrikeClient(
            server_url=args.server,
            timeout=args.timeout,
            cache_size=args.cache_size,
            cache_ttl=args.cache_ttl,
            rate_limit_rps=args.rate_limit,
            rate_limit_burst=args.rate_burst
        )

        health = hexstrike_client.check_health()
        if "error" in health:
            logger.warning(f"⚠️  Unable to connect: {health['error']}")
            logger.warning("🚀 MCP server will start, but tool execution may fail")
        else:
            logger.info(f"🎯 Successfully connected to HexStrike AI API server")
            logger.info(f"🏥 Server health status: {health.get('status')}")
            logger.info(f"📊 Version: {health.get('version', 'unknown')}")

        mcp = setup_mcp_server(hexstrike_client)
        logger.info("🚀 Starting HexStrike AI MCP server")
        logger.info("🤖 Ready to serve AI agents with enhanced cybersecurity capabilities")
        mcp.run()
    except Exception as e:
        logger.error(f"💥 Error starting MCP server: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
