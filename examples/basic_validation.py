"""
Basic webhook validation example using WebhookValidator.

This example shows how to use the basic WebhookValidator for simple
signature verification and timestamp checking.
"""

from webhook_guardian import WebhookValidator


def basic_webhook_handler():
    """Example of basic webhook validation."""
    
    # Initialize validator with your webhook secret
    secret = "your-webhook-secret-key"
    validator = WebhookValidator(secret, tolerance_seconds=300)
    
    # Example webhook data (normally from HTTP request)
    payload = '{"event": "payment.success", "amount": 100, "user_id": 12345}'
    signature = "sha256=a8b2c3d4e5f6..."  # From webhook headers
    timestamp = "1640995200"  # Unix timestamp from headers
    
    try:
        # Validate the webhook
        is_valid = validator.verify_request(
            payload=payload,
            signature=signature,
            timestamp=timestamp
        )
        
        if is_valid:
            print("✅ Webhook is valid! Processing...")
            # Process your webhook data here
            process_webhook_data(payload)
        else:
            print("❌ Invalid webhook - rejecting")
            
    except Exception as e:
        print(f"❌ Webhook validation failed: {e}")


def signature_only_validation():
    """Example of signature-only validation (no timestamp check)."""
    
    validator = WebhookValidator("my-secret")
    payload = '{"event": "user.created", "user_id": 67890}'
    signature = "sha256=computed_signature_hash"
    
    try:
        # Validate only the signature
        is_valid = validator.verify_signature(payload, signature)
        
        if is_valid:
            print("✅ Signature is valid!")
        else:
            print("❌ Invalid signature")
            
    except Exception as e:
        print(f"❌ Signature validation error: {e}")


def manual_signature_generation():
    """Example of generating a signature (for testing purposes)."""
    
    validator = WebhookValidator("test-secret")
    payload = '{"test": "data"}'
    
    # Generate signature (this is what the webhook sender would do)
    signature = validator._compute_signature(payload)
    print(f"Generated signature: {signature}")
    
    # Verify the signature
    is_valid = validator.verify_signature(payload, signature)
    print(f"Signature verification: {'✅ Valid' if is_valid else '❌ Invalid'}")


def process_webhook_data(payload: str):
    """Process validated webhook data."""
    import json
    
    try:
        data = json.loads(payload)
        event_type = data.get('event')
        
        print(f"Processing {event_type} event...")
        # Add your business logic here
        
    except json.JSONDecodeError:
        print("Error: Invalid JSON payload")


if __name__ == "__main__":
    print("=== Basic Webhook Validation Examples ===\n")
    
    print("1. Basic webhook validation:")
    basic_webhook_handler()
    
    print("\n2. Signature-only validation:")
    signature_only_validation()
    
    print("\n3. Manual signature generation:")
    manual_signature_generation()
