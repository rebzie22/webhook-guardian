"""
Advanced webhook security example using WebhookGuardian.

This example demonstrates comprehensive webhook security with IP whitelisting,
rate limiting, payload size validation, and detailed security logging.
"""

from webhook_guardian import WebhookGuardian


def advanced_webhook_handler():
    """Example of advanced webhook validation with all security features."""
    
    # Configure comprehensive security settings
    guardian = WebhookGuardian(
        secret="super-secure-webhook-secret",
        tolerance_seconds=300,  # 5 minutes tolerance for timestamp
        allowed_ips=[
            "192.168.1.0/24",    # Local network
            "10.0.0.0/8",        # Private network
            "203.0.113.1"        # Specific webhook provider IP
        ],
        max_payload_size=1024 * 1024,  # 1MB limit
        rate_limit={
            "requests": 100,      # Max 100 requests
            "window": 3600        # Per hour (3600 seconds)
        },
        enable_logging=True
    )
    
    # Example webhook request data
    payload = '{"event": "order.completed", "order_id": "ORD-123", "amount": 99.99}'
    signature = "sha256=computed_hmac_signature"
    client_ip = "192.168.1.100"  # IP from request
    timestamp = "1640995200"
    
    # Validate the webhook with all security checks
    result = guardian.validate_webhook(
        payload=payload,
        signature=signature,
        client_ip=client_ip,
        timestamp=timestamp
    )
    
    if result.is_valid:
        print("✅ Webhook passed all security checks!")
        print(f"Validation details: {result.validation_details}")
        
        # Process the webhook safely
        process_secure_webhook(payload)
        
    else:
        print(f"❌ Webhook validation failed: {result.error_message}")
        print(f"Error type: {result.error_type}")
        print(f"Details: {result.validation_details}")
        
        # Log security incident
        log_security_incident(result, client_ip)


def rate_limiting_example():
    """Example demonstrating rate limiting functionality."""
    
    guardian = WebhookGuardian(
        secret="test-secret",
        rate_limit={"requests": 3, "window": 60}  # 3 requests per minute
    )
    
    payload = '{"test": "data"}'
    signature = guardian.validator._compute_signature(payload)
    client_ip = "203.0.113.5"
    
    print("Testing rate limiting (3 requests per minute):")
    
    for i in range(5):
        result = guardian.validate_webhook(payload, signature, client_ip)
        
        if result.is_valid:
            print(f"Request {i+1}: ✅ Accepted")
        else:
            print(f"Request {i+1}: ❌ {result.error_message}")
        
        # Check rate limit status
        status = guardian.get_rate_limit_status(client_ip)
        print(f"  Rate limit status: {status['current_requests']}/{status['max_requests']} requests")


def ip_whitelist_example():
    """Example demonstrating IP whitelist functionality."""
    
    guardian = WebhookGuardian(
        secret="test-secret",
        allowed_ips=["192.168.1.0/24", "10.0.0.1"]
    )
    
    payload = '{"event": "test"}'
    signature = guardian.validator._compute_signature(payload)
    
    test_ips = [
        ("192.168.1.100", "Allowed - in subnet"),
        ("10.0.0.1", "Allowed - exact match"),
        ("203.0.113.1", "Denied - not in whitelist"),
        ("127.0.0.1", "Denied - not in whitelist")
    ]
    
    print("Testing IP whitelist:")
    
    for ip, description in test_ips:
        result = guardian.validate_webhook(payload, signature, ip)
        status = "✅ Allowed" if result.is_valid else "❌ Denied"
        print(f"  {ip}: {status} - {description}")


def payload_size_example():
    """Example demonstrating payload size validation."""
    
    guardian = WebhookGuardian(
        secret="test-secret",
        max_payload_size=100  # Very small limit for demo
    )
    
    small_payload = '{"event": "small"}'
    large_payload = '{"event": "large", "data": "' + "x" * 200 + '"}'
    
    test_payloads = [
        (small_payload, "Small payload"),
        (large_payload, "Large payload")
    ]
    
    print("Testing payload size limits (100 bytes max):")
    
    for payload, description in test_payloads:
        signature = guardian.validator._compute_signature(payload)
        result = guardian.validate_webhook(payload, signature, "192.168.1.1")
        
        payload_size = len(payload.encode('utf-8'))
        status = "✅ Accepted" if result.is_valid else "❌ Rejected"
        print(f"  {description} ({payload_size} bytes): {status}")


def process_secure_webhook(payload: str):
    """Process a validated webhook with additional security measures."""
    import json
    
    try:
        data = json.loads(payload)
        event_type = data.get('event')
        
        print(f"🔒 Securely processing {event_type} event")
        
        # Add your secure business logic here
        # - Validate data schemas
        # - Check business rules
        # - Update databases safely
        # - Send notifications
        
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON in webhook payload")


def log_security_incident(result, client_ip: str):
    """Log security incidents for monitoring and analysis."""
    import datetime
    
    incident = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "client_ip": client_ip,
        "error_type": result.error_type,
        "error_message": result.error_message,
        "validation_details": result.validation_details
    }
    
    print(f"🚨 Security incident logged: {incident}")
    # In production, send to your logging/monitoring system


if __name__ == "__main__":
    print("=== Advanced Webhook Security Examples ===\n")
    
    print("1. Complete webhook validation:")
    advanced_webhook_handler()
    
    print("\n2. Rate limiting demo:")
    rate_limiting_example()
    
    print("\n3. IP whitelist demo:")
    ip_whitelist_example()
    
    print("\n4. Payload size validation:")
    payload_size_example()
