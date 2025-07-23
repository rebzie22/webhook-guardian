"""Tests for the WebhookGuardian class."""

import pytest
from unittest.mock import patch

from webhook_guardian import WebhookGuardian
from webhook_guardian.exceptions import UnauthorizedIPError, RateLimitError, PayloadTooLargeError


class TestWebhookGuardian:
    def test_check_payload_size_invalid_type(self):
        """Test _check_payload_size with invalid type (object)."""
        guardian = WebhookGuardian(self.secret, max_payload_size=10)
        class Dummy: pass
        with pytest.raises(Exception):
            guardian._check_payload_size(Dummy())

    def test_validate_webhook_unexpected_error(self):
        """Test validate_webhook handles unexpected error gracefully."""
        guardian = WebhookGuardian(self.secret)
        # Pass an object as payload to cause error
        class Dummy: pass
        signature = guardian.validator._compute_signature(self.test_payload)
        result = guardian.validate_webhook(
            payload=Dummy(),
            signature=signature,
            client_ip=self.test_ip
        )
        assert result.is_valid is False
        assert result.error_type == "AttributeError" or result.error_type == "TypeError"

    def test_init_with_rate_limit_missing_keys(self):
        """Test guardian initialization with missing rate_limit keys."""
        with pytest.raises(KeyError):
            WebhookGuardian(self.secret, rate_limit={"requests": 1})

    def test_rate_limiter_window_expiry(self):
        """Test rate limiter allows after window expiry."""
        rate_limit = {"requests": 1, "window": 1}
        guardian = WebhookGuardian(self.secret, rate_limit=rate_limit)
        signature = guardian.validator._compute_signature(self.test_payload)
        # First request
        result1 = guardian.validate_webhook(
            payload=self.test_payload,
            signature=signature,
            client_ip=self.test_ip
        )
        assert result1.is_valid is True
        # Wait for window to expire
        import time as t
        t.sleep(1.1)
        # Second request should succeed
        result2 = guardian.validate_webhook(
            payload=self.test_payload,
            signature=signature,
            client_ip=self.test_ip
        )
        assert result2.is_valid is True
    def test_init_with_invalid_ip_range(self):
        """Test guardian initialization fails with invalid IP range."""
        with pytest.raises(ValueError, match="Invalid IP range"):
            WebhookGuardian(self.secret, allowed_ips=["999.999.999.999/99"])

    def test_check_ip_whitelist_malformed_ip(self):
        """Test _check_ip_whitelist returns False for malformed IP address."""
        guardian = WebhookGuardian(self.secret, allowed_ips=["192.168.1.0/24"])
        assert guardian._check_ip_whitelist("bad_ip_address") is False
    def test_check_ip_whitelist_invalid_ip(self):
        """Test _check_ip_whitelist returns False for invalid IP address."""
        guardian = WebhookGuardian(self.secret, allowed_ips=["192.168.1.0/24"])
        assert guardian._check_ip_whitelist("not_an_ip") is False

    def test_check_payload_size_bytes(self):
        """Test _check_payload_size with bytes payload."""
        guardian = WebhookGuardian(self.secret, max_payload_size=10)
        payload = b"1234567890"
        assert guardian._check_payload_size(payload) is True
        payload = b"12345678901"
        assert guardian._check_payload_size(payload) is False

    def test_get_rate_limit_status_disabled(self):
        """Test get_rate_limit_status returns disabled when no rate limiter."""
        guardian = WebhookGuardian(self.secret)
        status = guardian.get_rate_limit_status(self.test_ip)
        assert status["rate_limiting"] == "disabled"
    """Test cases for WebhookGuardian."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.secret = "test-secret"
        self.test_payload = '{"event": "test"}'
        self.test_ip = "192.168.1.100"
    
    def test_init_basic(self):
        """Test basic guardian initialization."""
        guardian = WebhookGuardian(self.secret)
        assert guardian.validator.secret == self.secret.encode('utf-8')
    
    def test_init_with_ip_whitelist(self):
        """Test guardian initialization with IP whitelist."""
        allowed_ips = ["192.168.1.0/24", "10.0.0.1"]
        guardian = WebhookGuardian(self.secret, allowed_ips=allowed_ips)
        assert len(guardian.allowed_networks) == 2
    
    def test_init_with_invalid_ip(self):
        """Test guardian initialization fails with invalid IP."""
        with pytest.raises(ValueError, match="Invalid IP range"):
            WebhookGuardian(self.secret, allowed_ips=["invalid_ip"])
    
    def test_init_with_rate_limit(self):
        """Test guardian initialization with rate limiting."""
        rate_limit = {"requests": 100, "window": 3600}
        guardian = WebhookGuardian(self.secret, rate_limit=rate_limit)
        assert guardian.rate_limiter is not None
        assert guardian.rate_limiter.max_requests == 100
    
    def test_check_ip_whitelist_allowed(self):
        """Test IP whitelist check with allowed IP."""
        guardian = WebhookGuardian(self.secret, allowed_ips=["192.168.1.0/24"])
        assert guardian._check_ip_whitelist("192.168.1.100") is True
    
    def test_check_ip_whitelist_denied(self):
        """Test IP whitelist check with denied IP."""
        guardian = WebhookGuardian(self.secret, allowed_ips=["192.168.1.0/24"])
        assert guardian._check_ip_whitelist("10.0.0.1") is False
    
    def test_check_ip_whitelist_no_restriction(self):
        """Test IP whitelist check with no restrictions."""
        guardian = WebhookGuardian(self.secret)
        assert guardian._check_ip_whitelist("any.ip.address") is True
    
    def test_check_payload_size_allowed(self):
        """Test payload size check within limits."""
        guardian = WebhookGuardian(self.secret, max_payload_size=1024)
        small_payload = "small payload"
        assert guardian._check_payload_size(small_payload) is True
    
    def test_check_payload_size_exceeded(self):
        """Test payload size check exceeding limits."""
        guardian = WebhookGuardian(self.secret, max_payload_size=10)
        large_payload = "this payload is too large"
        assert guardian._check_payload_size(large_payload) is False
    
    def test_check_payload_size_no_limit(self):
        """Test payload size check with no size limit."""
        guardian = WebhookGuardian(self.secret)
        large_payload = "x" * 10000
        assert guardian._check_payload_size(large_payload) is True
    
    def test_validate_webhook_success(self):
        """Test successful webhook validation."""
        guardian = WebhookGuardian(self.secret)
        signature = guardian.validator._compute_signature(self.test_payload)
        
        result = guardian.validate_webhook(
            payload=self.test_payload,
            signature=signature,
            client_ip=self.test_ip
        )
        
        assert result.is_valid is True
        assert result.error_message is None
        assert "signature_check" in result.validation_details
    
    def test_validate_webhook_ip_denied(self):
        """Test webhook validation with unauthorized IP."""
        guardian = WebhookGuardian(self.secret, allowed_ips=["10.0.0.0/8"])
        signature = guardian.validator._compute_signature(self.test_payload)
        
        result = guardian.validate_webhook(
            payload=self.test_payload,
            signature=signature,
            client_ip="192.168.1.100"  # Not in allowed range
        )
        
        assert result.is_valid is False
        assert result.error_type == "UnauthorizedIP"
        assert "not in whitelist" in result.error_message
    
    def test_validate_webhook_payload_too_large(self):
        """Test webhook validation with oversized payload."""
        guardian = WebhookGuardian(self.secret, max_payload_size=10)
        large_payload = "this payload exceeds the size limit"
        signature = guardian.validator._compute_signature(large_payload)
        
        result = guardian.validate_webhook(
            payload=large_payload,
            signature=signature,
            client_ip=self.test_ip
        )
        
        assert result.is_valid is False
        assert result.error_type == "PayloadTooLarge"
        assert "Payload too large" in result.error_message
    
    def test_validate_webhook_rate_limited(self):
        """Test webhook validation with rate limiting."""
        rate_limit = {"requests": 1, "window": 3600}
        guardian = WebhookGuardian(self.secret, rate_limit=rate_limit)
        signature = guardian.validator._compute_signature(self.test_payload)
        
        # First request should succeed
        result1 = guardian.validate_webhook(
            payload=self.test_payload,
            signature=signature,
            client_ip=self.test_ip
        )
        assert result1.is_valid is True
        
        # Second request should be rate limited
        result2 = guardian.validate_webhook(
            payload=self.test_payload,
            signature=signature,
            client_ip=self.test_ip
        )
        assert result2.is_valid is False
        assert result2.error_type == "RateLimit"
    
    def test_validate_webhook_invalid_signature(self):
        """Test webhook validation with invalid signature."""
        guardian = WebhookGuardian(self.secret)
        invalid_signature = "sha256=invalid_hash"
        
        result = guardian.validate_webhook(
            payload=self.test_payload,
            signature=invalid_signature,
            client_ip=self.test_ip
        )
        
        assert result.is_valid is False
        assert result.error_type == "InvalidSignature"
    
    def test_validate_webhook_catches_unexpected_exception(self):
        """Test webhook validation catches unexpected exceptions."""
        guardian = WebhookGuardian(self.secret)
        class Dummy: pass
        signature = guardian.validator._compute_signature(self.test_payload)
        result = guardian.validate_webhook(
            payload=Dummy(),  # This will cause an AttributeError
            signature=signature,
            client_ip=self.test_ip
        )
        assert result.is_valid is False
        assert result.error_type in ("AttributeError", "TypeError")
        assert "Validation error" in result.error_message

    def test_get_rate_limit_status_disabled(self):
        """Test rate limit status when disabled."""
        guardian = WebhookGuardian(self.secret)
        status = guardian.get_rate_limit_status(self.test_ip)
        assert status["rate_limiting"] == "disabled"
    
    def test_get_rate_limit_status_enabled(self):
        """Test rate limit status when enabled."""
        rate_limit = {"requests": 100, "window": 3600}
        guardian = WebhookGuardian(self.secret, rate_limit=rate_limit)
        
        status = guardian.get_rate_limit_status(self.test_ip)
        assert status["max_requests"] == 100
        assert status["current_requests"] == 0
        assert status["requests_remaining"] == 100
