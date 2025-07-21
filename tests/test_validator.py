"""Tests for the WebhookValidator class."""

import pytest
import time
from unittest.mock import patch

from webhook_guardian import WebhookValidator
from webhook_guardian.exceptions import InvalidSignatureError, ReplayAttackError


class TestWebhookValidator:
    """Test cases for WebhookValidator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.secret = "test-secret-key"
        self.validator = WebhookValidator(self.secret)
        self.test_payload = '{"event": "test", "data": {"user_id": 123}}'
    
    def test_init_with_valid_params(self):
        """Test validator initialization with valid parameters."""
        validator = WebhookValidator("secret", tolerance_seconds=600)
        assert validator.tolerance_seconds == 600
    
    def test_init_with_empty_secret(self):
        """Test validator initialization fails with empty secret."""
        with pytest.raises(ValueError, match="Secret key cannot be empty"):
            WebhookValidator("")
    
    def test_init_with_negative_tolerance(self):
        """Test validator initialization fails with negative tolerance."""
        with pytest.raises(ValueError, match="Tolerance seconds must be non-negative"):
            WebhookValidator("secret", tolerance_seconds=-1)
    
    def test_compute_signature(self):
        """Test signature computation."""
        signature = self.validator._compute_signature(self.test_payload)
        assert signature.startswith("sha256=")
        assert len(signature) == 71  # "sha256=" + 64 hex chars
    
    def test_compute_signature_with_bytes(self):
        """Test signature computation with bytes payload."""
        payload_bytes = self.test_payload.encode('utf-8')
        signature = self.validator._compute_signature(payload_bytes)
        assert signature.startswith("sha256=")
    
    def test_verify_signature_valid(self):
        """Test signature verification with valid signature."""
        signature = self.validator._compute_signature(self.test_payload)
        assert self.validator.verify_signature(self.test_payload, signature) is True
    
    def test_verify_signature_invalid(self):
        """Test signature verification with invalid signature."""
        invalid_signature = "sha256=invalid_signature_hash"
        assert self.validator.verify_signature(self.test_payload, invalid_signature) is False
    
    def test_verify_signature_empty(self):
        """Test signature verification fails with empty signature."""
        with pytest.raises(InvalidSignatureError, match="Signature cannot be empty"):
            self.validator.verify_signature(self.test_payload, "")
    
    def test_verify_signature_invalid_format(self):
        """Test signature verification fails with invalid format."""
        with pytest.raises(InvalidSignatureError, match="Invalid signature format"):
            self.validator.verify_signature(self.test_payload, "invalid_format")
    
    def test_verify_timestamp_valid(self):
        """Test timestamp verification with valid timestamp."""
        current_time = time.time()
        assert self.validator.verify_timestamp(current_time, current_time) is True
    
    def test_verify_timestamp_within_tolerance(self):
        """Test timestamp verification within tolerance."""
        current_time = time.time()
        old_timestamp = current_time - 100  # 100 seconds ago, within default tolerance
        assert self.validator.verify_timestamp(old_timestamp, current_time) is True
    
    def test_verify_timestamp_too_old(self):
        """Test timestamp verification fails when too old."""
        current_time = time.time()
        old_timestamp = current_time - 400  # 400 seconds ago, beyond default tolerance
        with pytest.raises(ReplayAttackError, match="Webhook is too old"):
            self.validator.verify_timestamp(old_timestamp, current_time)
    
    def test_verify_timestamp_future(self):
        """Test timestamp verification fails when in future."""
        current_time = time.time()
        future_timestamp = current_time + 400  # 400 seconds in future
        with pytest.raises(ReplayAttackError, match="Webhook is from the future"):
            self.validator.verify_timestamp(future_timestamp, current_time)
    
    def test_verify_timestamp_invalid_format(self):
        """Test timestamp verification fails with invalid format."""
        with pytest.raises(ReplayAttackError, match="Invalid timestamp format"):
            self.validator.verify_timestamp("not_a_number")
    
    def test_verify_request_valid_with_timestamp(self):
        """Test full request verification with valid signature and timestamp."""
        signature = self.validator._compute_signature(self.test_payload)
        current_time = time.time()
        
        result = self.validator.verify_request(
            self.test_payload, 
            signature, 
            current_time
        )
        assert result is True
    
    def test_verify_request_valid_without_timestamp(self):
        """Test request verification without timestamp."""
        signature = self.validator._compute_signature(self.test_payload)
        
        result = self.validator.verify_request(
            self.test_payload, 
            signature
        )
        assert result is True
    
    def test_verify_request_invalid_signature(self):
        """Test request verification fails with invalid signature."""
        invalid_signature = "sha256=invalid_hash"
        
        result = self.validator.verify_request(
            self.test_payload, 
            invalid_signature
        )
        assert result is False
    
    def test_verify_request_invalid_timestamp(self):
        """Test request verification fails with invalid timestamp."""
        signature = self.validator._compute_signature(self.test_payload)
        old_timestamp = time.time() - 400  # Too old
        
        with pytest.raises(ReplayAttackError):
            self.validator.verify_request(
                self.test_payload, 
                signature, 
                old_timestamp
            )
