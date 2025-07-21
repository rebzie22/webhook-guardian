"""
Advanced webhook security with comprehensive protection features.

This module provides the WebhookGuardian class with additional security features
like IP whitelisting, rate limiting, and payload size validation.
"""

import ipaddress
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass

from .validator import WebhookValidator
from .exceptions import (
    UnauthorizedIPError,
    RateLimitError,
    PayloadTooLargeError
)


@dataclass
class ValidationResult:
    """Result of webhook validation with detailed information."""
    is_valid: bool
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    validation_details: Optional[Dict[str, Any]] = None


class RateLimiter:
    """Simple in-memory rate limiter using sliding window."""
    
    def __init__(self, max_requests: int, window_seconds: int):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in the window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed for the given identifier.
        
        Args:
            identifier: Unique identifier (e.g., IP address)
            
        Returns:
            True if request is allowed, False if rate limited
        """
        now = time.time()
        cutoff = now - self.window_seconds
        
        # Remove old requests
        requests = self.requests[identifier]
        while requests and requests[0] < cutoff:
            requests.popleft()
        
        # Check if under limit
        if len(requests) >= self.max_requests:
            return False
        
        # Add current request
        requests.append(now)
        return True


class WebhookGuardian:
    """
    Advanced webhook validator with comprehensive security features.
    
    Provides all the functionality of WebhookValidator plus additional security
    features like IP whitelisting, rate limiting, and payload size validation.
    
    Example:
        >>> guardian = WebhookGuardian(
        ...     secret="my-secret",
        ...     allowed_ips=["192.168.1.0/24"],
        ...     max_payload_size=1024*1024,
        ...     rate_limit={"requests": 100, "window": 3600}
        ... )
        >>> result = guardian.validate_webhook(request)
        >>> if result.is_valid:
        ...     process_webhook(request)
    """
    
    def __init__(self, 
                 secret: str,
                 tolerance_seconds: int = 300,
                 allowed_ips: Optional[List[str]] = None,
                 max_payload_size: Optional[int] = None,
                 rate_limit: Optional[Dict[str, int]] = None,
                 enable_logging: bool = False):
        """
        Initialize the webhook guardian.
        
        Args:
            secret: Shared secret for HMAC validation
            tolerance_seconds: Maximum age of webhook in seconds
            allowed_ips: List of allowed IP addresses/ranges (CIDR notation supported)
            max_payload_size: Maximum payload size in bytes
            rate_limit: Dict with 'requests' and 'window' keys for rate limiting
            enable_logging: Enable request logging (for monitoring)
        """
        self.validator = WebhookValidator(secret, tolerance_seconds)
        self.allowed_networks = []
        self.max_payload_size = max_payload_size
        self.enable_logging = enable_logging
        self.rate_limiter = None
        
        # Parse allowed IPs
        if allowed_ips:
            for ip_range in allowed_ips:
                try:
                    self.allowed_networks.append(ipaddress.ip_network(ip_range, strict=False))
                except ValueError as e:
                    raise ValueError(f"Invalid IP range '{ip_range}': {e}")
        
        # Setup rate limiter
        if rate_limit:
            self.rate_limiter = RateLimiter(
                rate_limit['requests'], 
                rate_limit['window']
            )
    
    def _check_ip_whitelist(self, client_ip: str) -> bool:
        """
        Check if client IP is in the whitelist.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if IP is allowed or no whitelist configured
        """
        if not self.allowed_networks:
            return True  # No whitelist configured
        
        try:
            client_addr = ipaddress.ip_address(client_ip)
            return any(client_addr in network for network in self.allowed_networks)
        except ValueError:
            return False  # Invalid IP address
    
    def _check_payload_size(self, payload: Union[str, bytes]) -> bool:
        """
        Check if payload size is within limits.
        
        Args:
            payload: Webhook payload
            
        Returns:
            True if size is acceptable
        """
        if self.max_payload_size is None:
            return True
        
        if isinstance(payload, str):
            size = len(payload.encode('utf-8'))
        else:
            size = len(payload)
        
        return size <= self.max_payload_size
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """
        Check if request is within rate limits.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if request is allowed
        """
        if self.rate_limiter is None:
            return True
        
        return self.rate_limiter.is_allowed(client_ip)
    
    def validate_webhook(self, 
                        payload: Union[str, bytes],
                        signature: str,
                        client_ip: str,
                        timestamp: Optional[Union[str, int, float]] = None) -> ValidationResult:
        """
        Perform comprehensive webhook validation.
        
        Args:
            payload: Webhook payload
            signature: Webhook signature
            client_ip: Client IP address
            timestamp: Optional timestamp
            
        Returns:
            ValidationResult with validation outcome and details
        """
        details = {}
        
        try:
            # Check IP whitelist
            if not self._check_ip_whitelist(client_ip):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"IP address {client_ip} not in whitelist",
                    error_type="UnauthorizedIP",
                    validation_details={"client_ip": client_ip}
                )
            details["ip_check"] = "passed"
            
            # Check rate limits
            if not self._check_rate_limit(client_ip):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Rate limit exceeded for IP {client_ip}",
                    error_type="RateLimit",
                    validation_details={"client_ip": client_ip}
                )
            details["rate_limit_check"] = "passed"
            
            # Check payload size
            if not self._check_payload_size(payload):
                payload_size = len(payload.encode('utf-8') if isinstance(payload, str) else payload)
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Payload too large: {payload_size} bytes (max: {self.max_payload_size})",
                    error_type="PayloadTooLarge",
                    validation_details={"payload_size": payload_size, "max_size": self.max_payload_size}
                )
            details["payload_size_check"] = "passed"
            
            # Validate signature and timestamp
            if self.validator.verify_request(payload, signature, timestamp):
                details["signature_check"] = "passed"
                if timestamp:
                    details["timestamp_check"] = "passed"
                
                return ValidationResult(
                    is_valid=True,
                    validation_details=details
                )
            else:
                return ValidationResult(
                    is_valid=False,
                    error_message="Invalid signature or timestamp",
                    error_type="InvalidSignature",
                    validation_details=details
                )
                
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Validation error: {str(e)}",
                error_type=type(e).__name__,
                validation_details=details
            )
    
    def get_rate_limit_status(self, client_ip: str) -> Dict[str, Any]:
        """
        Get rate limit status for a client IP.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Dictionary with rate limit information
        """
        if self.rate_limiter is None:
            return {"rate_limiting": "disabled"}
        
        requests = self.rate_limiter.requests.get(client_ip, deque())
        current_count = len(requests)
        
        return {
            "current_requests": current_count,
            "max_requests": self.rate_limiter.max_requests,
            "window_seconds": self.rate_limiter.window_seconds,
            "requests_remaining": max(0, self.rate_limiter.max_requests - current_count)
        }
