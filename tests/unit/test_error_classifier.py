"""Unit tests for hexstrike_mcp.ErrorClassifier and EnhancedError."""
import requests
import aiohttp
import pytest

from hexstrike_mcp import ErrorClassifier, EnhancedError, ErrorCategory, ErrorSeverity


class TestEnhancedErrorToDict:
    def test_serializes_enum_values(self):
        err = EnhancedError(
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.HIGH,
            message="boom",
        )
        d = err.to_dict()
        assert d["category"] == "network"
        assert d["severity"] == "high"
        assert d["message"] == "boom"
        assert d["recoverable"] is True
        assert d["retry_count"] == 0

    def test_excludes_non_serializable_original_error(self):
        err = EnhancedError(
            category=ErrorCategory.UNKNOWN,
            severity=ErrorSeverity.MEDIUM,
            message="x",
            original_error=ValueError("inner"),
        )
        d = err.to_dict()
        assert "original_error" not in d
        assert d["recovery_hint"] == ""


class TestClassifyHttpStatus:
    @pytest.mark.parametrize("status,category,severity,recoverable", [
        (401, ErrorCategory.AUTH, ErrorSeverity.HIGH, False),
        (403, ErrorCategory.AUTH, ErrorSeverity.HIGH, False),
        (429, ErrorCategory.RATE_LIMIT, ErrorSeverity.MEDIUM, True),
        (500, ErrorCategory.SERVER, ErrorSeverity.HIGH, True),
        (502, ErrorCategory.SERVER, ErrorSeverity.HIGH, True),
        (503, ErrorCategory.SERVER, ErrorSeverity.MEDIUM, True),
        (504, ErrorCategory.TIMEOUT, ErrorSeverity.HIGH, True),
    ])
    def test_status_mapping(self, status, category, severity, recoverable):
        err = ErrorClassifier.classify(RuntimeError("x"), http_status=status)
        assert err.category == category
        assert err.severity == severity
        assert err.recoverable == recoverable

    def test_auth_recovery_hint_mentions_credentials(self):
        err = ErrorClassifier.classify(RuntimeError("x"), http_status=401)
        assert "credentials" in err.recovery_hint.lower()


class TestClassifyException:
    def test_timeout_exception(self):
        err = ErrorClassifier.classify(requests.exceptions.Timeout("t/o"))
        assert err.category == ErrorCategory.TIMEOUT
        assert err.severity == ErrorSeverity.HIGH
        assert err.recoverable is True

    def test_connection_error(self):
        err = ErrorClassifier.classify(requests.exceptions.ConnectionError("down"))
        assert err.category == ErrorCategory.NETWORK
        assert err.recoverable is True

    def test_http_error(self):
        err = ErrorClassifier.classify(requests.exceptions.HTTPError("500"))
        assert err.category == ErrorCategory.SERVER
        assert err.recoverable is False  # SERVER not in [NETWORK, TIMEOUT]

    def test_unknown_fallback(self):
        err = ErrorClassifier.classify(ValueError("weird"))
        assert err.category == ErrorCategory.UNKNOWN
        assert err.severity == ErrorSeverity.MEDIUM
        assert err.recoverable is True

    def test_http_status_takes_precedence_over_exception_type(self):
        # A Timeout exception but with explicit 401 status -> AUTH wins
        err = ErrorClassifier.classify(requests.exceptions.Timeout("t"), http_status=401)
        assert err.category == ErrorCategory.AUTH
