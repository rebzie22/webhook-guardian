"""Tests for the WebhookValidator class."""

import pytest
import time
from unittest.mock import patch

from webhook_guardian import WebhookValidator
from webhook_guardian.exceptions import InvalidSignatureError, ReplayAttackError


class TestWebhookValidator:
    def test_invalid_ed25519_public_key_pem_parse_error(self):
        """Test Ed25519 public key with PEM that triggers second except Exception block."""
        # This is a PEM that will parse as PEM but not as Ed25519, triggering the second except
        bad_pem = b"-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALeQw==\n-----END PUBLIC KEY-----"
        with pytest.raises(ValueError, match="Invalid Ed25519 public key"):
            WebhookValidator(self.secret, ed25519_public_key=bad_pem)
    def test_invalid_ed25519_public_key_pem(self):
        """Test PEM-encoded but invalid Ed25519 public key raises ValueError."""
        invalid_pem = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn\n-----END PUBLIC KEY-----"
        with pytest.raises(ValueError, match="Invalid Ed25519 public key"):
            WebhookValidator(self.secret, ed25519_public_key=invalid_pem)

    def test_compute_signature_ed25519_error(self):
        """Test _compute_signature with ed25519 algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Ed25519 signatures must be generated with a private key"):
            self.validator._compute_signature(self.test_payload, algorithm="ed25519")
    def test_invalid_ed25519_public_key(self):
        """Test invalid Ed25519 public key raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Ed25519 public key"):
            WebhookValidator(self.secret, ed25519_public_key=b'invalidkey')

    def test_unsupported_algorithm_compute_signature(self):
        """Test unsupported algorithm in _compute_signature raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            self.validator._compute_signature(self.test_payload, algorithm="unsupported")

    def test_unsupported_algorithm_verify_signature(self):
        """Test unsupported algorithm in verify_signature raises InvalidSignatureError."""
        signature = "unsupported=abcd"
        with pytest.raises(InvalidSignatureError, match="Unsupported algorithm"):
            self.validator.verify_signature(self.test_payload, signature)

    def test_ed25519_signature_missing_public_key(self):
        """Test Ed25519 signature verification fails if public key not set."""
        signature = "ed25519=abcd"
        with pytest.raises(InvalidSignatureError, match="Ed25519 public key not configured"):
            self.validator.verify_signature(self.test_payload, signature)

    def test_invalid_signature_format(self):
        """Test invalid signature format raises InvalidSignatureError."""
        with pytest.raises(InvalidSignatureError, match="Invalid signature format"):
            self.validator.verify_signature(self.test_payload, "invalidformat")

    def test_invalid_timestamp_type(self):
        """Test invalid timestamp type raises ReplayAttackError."""
        with pytest.raises(ReplayAttackError, match="Invalid timestamp format"):
            self.validator.verify_timestamp(object())
    def test_hmac_sha1_signature(self):
        """Test HMAC-SHA1 signature verification."""
        signature = self.validator._compute_signature(self.test_payload, algorithm="sha1")
        assert signature.startswith("sha1=")
        assert self.validator.verify_signature(self.test_payload, signature) is True

    def test_hmac_sha512_signature(self):
        """Test HMAC-SHA512 signature verification."""
        signature = self.validator._compute_signature(self.test_payload, algorithm="sha512")
        assert signature.startswith("sha512=")
        assert self.validator.verify_signature(self.test_payload, signature) is True

    def test_ed25519_signature(self):
        """Test Ed25519 signature verification."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        payload = self.test_payload.encode('utf-8')
        signature_bytes = private_key.sign(payload)
        signature = f"ed25519={signature_bytes.hex()}"
        validator = WebhookValidator(secret="irrelevant", ed25519_public_key=public_bytes)
        assert validator.verify_signature(payload, signature) is True

    def test_ed25519_invalid_signature(self):
        """Test Ed25519 signature verification fails with wrong signature."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        payload = self.test_payload.encode('utf-8')
        # Tamper with signature
        signature_bytes = b'0' * 64
        signature = f"ed25519={signature_bytes.hex()}"
        validator = WebhookValidator(secret="irrelevant", ed25519_public_key=public_bytes)
        assert validator.verify_signature(payload, signature) is False
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
