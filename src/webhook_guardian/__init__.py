"""
Webhook Guardian - A security-focused Python library for webhook validation.

This library provides tools for safely handling webhooks by validating signatures,
preventing replay attacks, and implementing security best practices.
"""

__version__ = "0.1.0"
__author__ = "Jordan Guck"
__email__ = "your.email@example.com"

from .validator import WebhookValidator
from .guardian import WebhookGuardian
from .exceptions import (
    WebhookGuardianError,
    InvalidSignatureError,
    ReplayAttackError,
    RateLimitError,
    PayloadTooLargeError,
    UnauthorizedIPError
)

__all__ = [
    "WebhookValidator",
    "WebhookGuardian", 
    "WebhookGuardianError",
    "InvalidSignatureError",
    "ReplayAttackError",
    "RateLimitError",
    "PayloadTooLargeError",
    "UnauthorizedIPError"
]
