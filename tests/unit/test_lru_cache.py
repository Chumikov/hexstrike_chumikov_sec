"""Unit tests for hexstrike_mcp.LRUCache (deterministic, no I/O)."""
import pytest

from hexstrike_mcp import LRUCache


class TestGenerateKey:
    def test_deterministic_for_same_input(self):
        c = LRUCache()
        k1 = c._generate_key("GET", "/health")
        k2 = c._generate_key("GET", "/health")
        assert k1 == k2

    def test_differs_by_method(self):
        c = LRUCache()
        assert c._generate_key("GET", "/x") != c._generate_key("POST", "/x")

    def test_differs_by_endpoint(self):
        c = LRUCache()
        assert c._generate_key("GET", "/a") != c._generate_key("GET", "/b")

    def test_differs_by_data(self):
        c = LRUCache()
        assert c._generate_key("POST", "/x", {"a": 1}) != c._generate_key("POST", "/x", {"a": 2})

    def test_data_order_invariant(self):
        c = LRUCache()
        assert c._generate_key("POST", "/x", {"a": 1, "b": 2}) == \
               c._generate_key("POST", "/x", {"b": 2, "a": 1})

    def test_none_data_equals_empty(self):
        c = LRUCache()
        assert c._generate_key("GET", "/x", None) == c._generate_key("GET", "/x", {})


class TestGetSet:
    def test_miss_on_empty(self, lru_cache):
        result, hit = lru_cache.get("GET", "/nope")
        assert hit is False
        assert result is None

    def test_set_then_hit(self, lru_cache):
        lru_cache.set("GET", "/health", {"status": "ok"})
        result, hit = lru_cache.get("GET", "/health")
        assert hit is True
        assert result == {"status": "ok"}

    def test_keyed_by_data(self, lru_cache):
        lru_cache.set("POST", "/x", {"r": 1}, data={"a": 1})
        result, hit = lru_cache.get("POST", "/x", data={"a": 1})
        assert hit is True and result == {"r": 1}
        _, miss = lru_cache.get("POST", "/x", data={"a": 2})
        assert miss is False


class TestEviction:
    def test_evicts_oldest_at_capacity(self):
        c = LRUCache(max_size=2)
        c.set("GET", "/a", {"r": "a"})
        c.set("GET", "/b", {"r": "b"})
        # touching /a should make /b the oldest
        c.get("GET", "/a")
        c.set("GET", "/c", {"r": "c"})  # over capacity -> evict oldest (/b)
        assert c.get("GET", "/b")[1] is False
        assert c.get("GET", "/a")[1] is True
        assert c.get("GET", "/c")[1] is True

    def test_overwrite_keeps_size(self, lru_cache):
        lru_cache.set("GET", "/x", {"v": 1})
        lru_cache.set("GET", "/x", {"v": 2})
        result, hit = lru_cache.get("GET", "/x")
        assert hit is True and result == {"v": 2}
        assert lru_cache.get_stats()["size"] == 1


class TestInvalidate:
    def test_invalidate_all(self, lru_cache):
        lru_cache.set("GET", "/a", {})
        lru_cache.set("GET", "/b", {})
        removed = lru_cache.invalidate()
        assert removed == 2
        assert lru_cache.get_stats()["size"] == 0

    def test_invalidate_by_pattern(self, lru_cache):
        lru_cache.set("GET", "/api/command", {})
        lru_cache.set("GET", "/health", {})
        # keys are sha256 hashes; pattern matches against hashed keys only,
        # so a plain path pattern will not match the hash -> 0 removed.
        removed = lru_cache.invalidate(pattern="/api")
        assert removed == 0
        assert lru_cache.get_stats()["size"] == 2


class TestStats:
    def test_initial_stats(self):
        c = LRUCache(max_size=10, default_ttl=300)
        stats = c.get_stats()
        assert stats["size"] == 0
        assert stats["max_size"] == 10
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["default_ttl"] == 300

    def test_hit_rate_tracks_hits_misses(self, lru_cache):
        lru_cache.set("GET", "/x", {})
        lru_cache.get("GET", "/x")   # hit
        lru_cache.get("GET", "/y")   # miss
        stats = lru_cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == "50.00%"
