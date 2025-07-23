# Webhook Guardian 🛡️

[![PyPI version](https://badge.fury.io/py/webhook-guardian.svg)](https://badge.fury.io/py/webhook-guardian)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-96%25%20coverage-brightgreen.svg)](tests/)

A beginner-friendly Python library for secure webhook handling and validation.

## 🎯 **What is Webhook Guardian?**

Webhook Guardian is a security-focused library that helps developers safely receive and validate webhooks from external services. It protects against common webhook security vulnerabilities like replay attacks, signature spoofing, and unauthorized requests.

## 🔒 **Security Features**

- **HMAC Signature Verification** - Verify webhooks are from trusted sources
- **Replay Attack Prevention** - Timestamp validation to prevent reused requests
- **Rate Limiting** - Protect against webhook spam and abuse
- **IP Whitelist Validation** - Only accept webhooks from authorized IPs
- **Request Size Limits** - Prevent oversized payload attacks
- **Comprehensive Logging** - Track and monitor webhook activity

## 🚀 **Quick Start**

### Installation

```bash
pip install webhook-guardian
```

### Basic Usage

```python
from webhook_guardian import WebhookValidator

# Initialize the validator with your secret
validator = WebhookValidator(
    secret="your-webhook-secret",
    tolerance_seconds=300  # Allow 5 minutes clock skew
)

# In your webhook endpoint
def handle_webhook(request):
    # Validate the webhook
    if validator.verify_request(
        payload=request.body,
        signature=request.headers.get('X-Hub-Signature-256'),
        timestamp=request.headers.get('X-Timestamp')
    ):
        # Process the webhook safely
        process_webhook_data(request.body)
        return {"status": "success"}
    else:
        # Reject invalid webhook
        return {"error": "Invalid webhook"}, 401
```


### Signature Algorithm Examples

#### HMAC-SHA1
```python
validator = WebhookValidator(secret="your-webhook-secret")
signature = validator._compute_signature(payload, algorithm="sha1")
is_valid = validator.verify_signature(payload, signature)
```

#### HMAC-SHA512
```python
validator = WebhookValidator(secret="your-webhook-secret")
signature = validator._compute_signature(payload, algorithm="sha512")
is_valid = validator.verify_signature(payload, signature)
```

#### Ed25519
```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Generate key pair (for demonstration; use secure key management in production)
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

payload = b"example webhook payload"
signature_bytes = private_key.sign(payload)
signature = f"ed25519={signature_bytes.hex()}"

# Validator with Ed25519 public key
validator = WebhookValidator(secret="irrelevant-for-ed25519", ed25519_public_key=public_bytes)
is_valid = validator.verify_signature(payload, signature)
```

### Advanced Configuration

```python
from webhook_guardian import WebhookGuardian

# Full-featured webhook handler
guardian = WebhookGuardian(
    secret="your-secret",
    allowed_ips=["192.168.1.100", "10.0.0.0/8"],
    max_payload_size=1024 * 1024,  # 1MB limit
    rate_limit={"requests": 100, "window": 3600},  # 100 req/hour
    enable_logging=True
)

# Validate with all security checks
result = guardian.validate_webhook(request)
if result.is_valid:
    process_webhook(request.body)
else:
    logger.warning(f"Invalid webhook: {result.error_message}")
```

## 📚 **Documentation**

- [Security Best Practices](docs/security.md)
- [API Reference](docs/api.md)
- [Examples](examples/)
- [Contributing Guide](CONTRIBUTING.md)

## 🧪 **Testing**

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=webhook_guardian
```

## 🛠️ **Development**

```bash
# Clone the repository
git clone https://github.com/rebzie22/webhook-guardian.git
cd webhook-guardian

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- Inspired by common webhook security vulnerabilities
- Built for developers who want to handle webhooks securely
- Designed with beginners in mind

## 📞 **Support**

- [Documentation](docs/)
- [Issue Tracker](https://github.com/rebzie22/webhook-guardian/issues)
- [Discussions](https://github.com/rebzie22/webhook-guardian/discussions)
