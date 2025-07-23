"""
Core webhook validation functionality.

This module provides the WebhookValidator class for basic webhook signature
validation and timestamp checking.
"""

import hashlib
import hmac
import time
from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature as CryptoInvalidSignature
from cryptography.hazmat.primitives import serialization

from .exceptions import InvalidSignatureError, ReplayAttackError


class WebhookValidator:
    """
    A simple webhook validator for signature verification and replay attack prevention.
    
    This class provides basic webhook security by validating HMAC signatures and
    checking timestamps to prevent replay attacks.
    
    Example:
        >>> validator = WebhookValidator("my-secret")
        >>> is_valid = validator.verify_request(
        ...     payload=b'{"event": "test"}',
        ...     signature="sha256=abcd1234...",
        ...     timestamp="1234567890"
        ... )
    """
    
    def __init__(self, secret: str, tolerance_seconds: int = 300, ed25519_public_key: Optional[Union[str, bytes]] = None):
        """
        Initialize the webhook validator.
        
        Args:
            secret: The shared secret key for HMAC validation
            tolerance_seconds: Maximum age of webhook in seconds (default: 300 = 5 minutes)
            ed25519_public_key: Optional Ed25519 public key (PEM or raw bytes) for Ed25519 validation
        Raises:
            ValueError: If secret is empty or tolerance_seconds is negative
        """
        if not secret:
            raise ValueError("Secret key cannot be empty")
        if tolerance_seconds < 0:
            raise ValueError("Tolerance seconds must be non-negative")
        self.secret = secret.encode('utf-8')
        self.tolerance_seconds = tolerance_seconds
        self.ed25519_public_key = None
        if ed25519_public_key:
            if isinstance(ed25519_public_key, str):
                ed25519_public_key = ed25519_public_key.encode('utf-8')
            try:
                self.ed25519_public_key = Ed25519PublicKey.from_public_bytes(ed25519_public_key)
            except Exception:
                try:
                    self.ed25519_public_key = serialization.load_pem_public_key(ed25519_public_key)
                except Exception as e:
                    raise ValueError(f"Invalid Ed25519 public key: {e}")
    
    def _compute_signature(self, payload: Union[str, bytes], algorithm: str = "sha256") -> str:
        """
        Compute HMAC signature for the given payload.
        
        Args:
            payload: The webhook payload to sign
            algorithm: Hash algorithm to use (sha1, sha256, sha512, ed25519)
        Returns:
            Computed signature in format "algorithm=hexdigest" (HMAC) or "ed25519=signaturehex" (Ed25519)
        Raises:
            ValueError: If algorithm is unsupported
        """
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        if algorithm in ("sha1", "sha256", "sha512"):
            mac = hmac.new(self.secret, payload, getattr(hashlib, algorithm))
            return f"{algorithm}={mac.hexdigest()}"
        elif algorithm == "ed25519":
            raise ValueError("Ed25519 signatures must be generated with a private key, not computed here.")
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def verify_signature(self, payload: Union[str, bytes], signature: str) -> bool:
        """
        Verify webhook signature using HMAC.
        
        Args:
            payload: The webhook payload
            signature: The signature to verify (format: "algorithm=hexdigest")
            
        Returns:
            True if signature is valid, False otherwise
            
        Raises:
            InvalidSignatureError: If signature format is invalid
        """
        if not signature:
            raise InvalidSignatureError("Signature cannot be empty")
        try:
            algorithm, provided_signature = signature.split('=', 1)
        except ValueError:
            raise InvalidSignatureError("Invalid signature format. Expected 'algorithm=hash'")
        if algorithm in ("sha1", "sha256", "sha512"):
            expected_signature = self._compute_signature(payload, algorithm)
            return hmac.compare_digest(signature, expected_signature)
        elif algorithm == "ed25519":
            if not self.ed25519_public_key:
                raise InvalidSignatureError("Ed25519 public key not configured for verification.")
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            try:
                # Ed25519 signature should be hex encoded
                signature_bytes = bytes.fromhex(provided_signature)
                self.ed25519_public_key.verify(signature_bytes, payload)
                return True
            except (ValueError, CryptoInvalidSignature):
                return False
        else:
            raise InvalidSignatureError(f"Unsupported algorithm: {algorithm}")
    
    def verify_timestamp(self, timestamp: Union[str, int, float], current_time: Optional[float] = None) -> bool:
        """
        Verify webhook timestamp to prevent replay attacks.
        
        Args:
            timestamp: Unix timestamp of the webhook
            current_time: Current time (for testing), defaults to time.time()
            
        Returns:
            True if timestamp is within tolerance, False otherwise
            
        Raises:
            ReplayAttackError: If timestamp is too old or in the future
        """
        if current_time is None:
            current_time = time.time()
        
        try:
            webhook_time = float(timestamp)
        except (ValueError, TypeError):
            raise ReplayAttackError("Invalid timestamp format")
        
        time_diff = abs(current_time - webhook_time)
        
        if time_diff > self.tolerance_seconds:
            if webhook_time < current_time:
                raise ReplayAttackError(f"Webhook is too old (age: {time_diff:.0f}s)")
            else:
                raise ReplayAttackError(f"Webhook is from the future (diff: {time_diff:.0f}s)")
        
        return True
    
    def verify_request(self, payload: Union[str, bytes], signature: str, 
                      timestamp: Optional[Union[str, int, float]] = None) -> bool:
        """
        Verify complete webhook request (signature and optionally timestamp).
        
        Args:
            payload: The webhook payload
            signature: The webhook signature
            timestamp: Optional timestamp for replay attack prevention
            
        Returns:
            True if webhook is valid, False otherwise
            
        Raises:
            InvalidSignatureError: If signature validation fails
            ReplayAttackError: If timestamp validation fails
        """
        # Always verify signature
        if not self.verify_signature(payload, signature):
            return False
        
        # Verify timestamp if provided
        if timestamp is not None:
            if not self.verify_timestamp(timestamp):
                return False
        
        return True
