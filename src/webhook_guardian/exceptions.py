"""Custom exceptions for webhook-guardian library."""


class WebhookGuardianError(Exception):
    """Base exception for all webhook guardian errors."""
    pass


class InvalidSignatureError(WebhookGuardianError):
    """Raised when webhook signature validation fails."""
    pass


class ReplayAttackError(WebhookGuardianError):
    """Raised when a potential replay attack is detected."""
    pass


class RateLimitError(WebhookGuardianError):
    """Raised when rate limit is exceeded."""
    pass


class PayloadTooLargeError(WebhookGuardianError):
    """Raised when webhook payload exceeds size limit."""
    pass


class UnauthorizedIPError(WebhookGuardianError):
    """Raised when webhook comes from unauthorized IP address."""
    pass
