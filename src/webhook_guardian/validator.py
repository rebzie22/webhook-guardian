"""
Core webhook validation functionality.

This module provides the WebhookValidator class for basic webhook signature
validation and timestamp checking.
"""

import hashlib
import hmac
import time
from typing import Optional, Union

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
    
    def __init__(self, secret: str, tolerance_seconds: int = 300):
        """
        Initialize the webhook validator.
        
        Args:
            secret: The shared secret key for HMAC validation
            tolerance_seconds: Maximum age of webhook in seconds (default: 300 = 5 minutes)
        
        Raises:
            ValueError: If secret is empty or tolerance_seconds is negative
        """
        if not secret:
            raise ValueError("Secret key cannot be empty")
        if tolerance_seconds < 0:
            raise ValueError("Tolerance seconds must be non-negative")
            
        self.secret = secret.encode('utf-8')
        self.tolerance_seconds = tolerance_seconds
    
    def _compute_signature(self, payload: Union[str, bytes], algorithm: str = "sha256") -> str:
        """
        Compute HMAC signature for the given payload.
        
        Args:
            payload: The webhook payload to sign
            algorithm: Hash algorithm to use (default: sha256)
            
        Returns:
            Computed signature in format "algorithm=hexdigest"
        """
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
            
        mac = hmac.new(self.secret, payload, getattr(hashlib, algorithm))
        return f"{algorithm}={mac.hexdigest()}"
    
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
            
        # Parse signature format: "sha256=abcd1234..."
        try:
            algorithm, provided_signature = signature.split('=', 1)
        except ValueError:
            raise InvalidSignatureError("Invalid signature format. Expected 'algorithm=hash'")
        
        # Compute expected signature
        expected_signature = self._compute_signature(payload, algorithm)
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(signature, expected_signature)
    
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
