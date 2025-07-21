# Development Setup for Webhook Guardian

Welcome to the webhook-guardian development environment! This guide will help you get started.

## 🚀 Quick Setup

### 1. Prerequisites
- Python 3.8 or higher
- Git
- pip (Python package manager)

### 2. Installation

**Option A: Development Installation**
```bash
# Clone your repository
git clone https://github.com/rebzie22/webhook-guardian.git
cd webhook-guardian

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

**Option B: User Installation**
```bash
pip install webhook-guardian
```

## 🧪 Running Tests

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=webhook_guardian

# Run specific test file
pytest tests/test_validator.py

# Run security-specific tests
pytest -m security
```

## 🔧 Development Tools

### Code Formatting
```bash
# Format code with Black
black src/ tests/ examples/

# Check code style with flake8
flake8 src/ tests/ examples/

# Type checking with mypy
mypy src/
```

### Running Examples
```bash
# Basic validation example
python examples/basic_validation.py

# Advanced security features
python examples/advanced_security.py

# Flask integration (requires Flask)
pip install flask
python examples/flask_integration.py
```

## 📚 Project Structure

```
webhook-guardian/
├── src/webhook_guardian/     # Main package
│   ├── __init__.py          # Package exports
│   ├── validator.py         # Basic webhook validation
│   ├── guardian.py          # Advanced security features
│   ├── exceptions.py        # Custom exceptions
│   └── cli.py              # Command-line interface
├── tests/                   # Test suite
│   ├── test_validator.py    # Validator tests
│   └── test_guardian.py     # Guardian tests
├── examples/               # Usage examples
│   ├── basic_validation.py  # Simple examples
│   ├── advanced_security.py # Advanced features
│   └── flask_integration.py # Web framework integration
├── docs/                   # Documentation (future)
├── setup.py               # Package setup (legacy)
├── pyproject.toml         # Modern package configuration
├── requirements.txt       # Dependencies
└── README.md             # Project documentation
```

## 🛡️ Security Features

This library provides multiple layers of webhook security:

1. **HMAC Signature Validation** - Verify webhook authenticity
2. **Timestamp Validation** - Prevent replay attacks
3. **IP Whitelisting** - Restrict webhook sources
4. **Rate Limiting** - Prevent abuse
5. **Payload Size Limits** - Prevent oversized attacks
6. **Comprehensive Logging** - Monitor security events

## 📖 Usage Examples

### Basic Usage
```python
from webhook_guardian import WebhookValidator

validator = WebhookValidator("your-secret")
is_valid = validator.verify_signature(payload, signature)
```

### Advanced Usage
```python
from webhook_guardian import WebhookGuardian

guardian = WebhookGuardian(
    secret="your-secret",
    allowed_ips=["192.168.1.0/24"],
    rate_limit={"requests": 100, "window": 3600}
)

result = guardian.validate_webhook(payload, signature, client_ip)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Run the test suite
6. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## 📞 Support

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support
- **Security Issues**: Email security concerns privately

---

**Happy webhook securing! 🛡️**
