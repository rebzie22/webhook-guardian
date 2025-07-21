# Contributing to Webhook Guardian

Thank you for your interest in contributing to Webhook Guardian! This document provides guidelines for contributing to this security-focused Python library.

## 🛡️ Security Focus

Since this is a security library, all contributions must maintain the highest security standards:

- **Security-first mindset**: Always consider security implications
- **No shortcuts**: Proper input validation, error handling, and cryptographic practices
- **Defense in depth**: Multiple layers of security validation
- **Fail securely**: When something goes wrong, fail in a secure manner

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment (recommended)

### Development Setup

1. **Fork and clone the repository**
```bash
git clone https://github.com/rebzie22/webhook-guardian.git
cd webhook-guardian
```

2. **Create a virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install development dependencies**
```bash
pip install -e ".[dev]"
```

4. **Install pre-commit hooks**
```bash
pre-commit install
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=webhook_guardian

# Run specific test file
pytest tests/test_validator.py

# Run security-specific tests
pytest -m security
```

### Test Requirements

- **100% test coverage** for security-critical functions
- **Both positive and negative test cases**
- **Edge case testing** (empty inputs, malformed data, etc.)
- **Security vulnerability testing** (replay attacks, timing attacks, etc.)
- **Performance testing** for rate limiting and validation

### Writing Tests

```python
def test_security_feature():
    """Test description focusing on security aspect."""
    # Arrange - Set up test data
    validator = WebhookValidator("secret")
    
    # Act - Perform the action
    result = validator.verify_signature(payload, signature)
    
    # Assert - Verify security behavior
    assert result is True
    
    # Test negative case
    with pytest.raises(InvalidSignatureError):
        validator.verify_signature(payload, "invalid_signature")
```

## 📝 Code Style

### Python Style Guide

- Follow **PEP 8** standards
- Use **type hints** for all function parameters and returns
- Write **comprehensive docstrings** with security considerations
- Use **descriptive variable names**

### Example Function

```python
def verify_signature(self, payload: Union[str, bytes], signature: str) -> bool:
    """
    Verify webhook signature using HMAC.
    
    Security considerations:
    - Uses constant-time comparison to prevent timing attacks
    - Validates signature format before processing
    - Handles both string and bytes payloads safely
    
    Args:
        payload: The webhook payload to verify
        signature: Expected signature in format "algorithm=hexdigest"
        
    Returns:
        True if signature is valid, False otherwise
        
    Raises:
        InvalidSignatureError: If signature format is invalid
        
    Example:
        >>> validator = WebhookValidator("secret")
        >>> is_valid = validator.verify_signature(b"data", "sha256=abc123")
    """
```

### Code Quality Tools

We use several tools to maintain code quality:

```bash
# Format code
black src/ tests/ examples/

# Check style
flake8 src/ tests/ examples/

# Type checking
mypy src/

# Run all checks
pre-commit run --all-files
```

## 🔒 Security Guidelines

### Cryptographic Best Practices

- **Use constant-time comparisons** for signature validation
- **Validate all inputs** before cryptographic operations
- **Use well-established libraries** (e.g., `cryptography`, `hashlib`)
- **Handle sensitive data carefully** (no logging, proper cleanup)

### Input Validation

- **Validate all external inputs** (payloads, signatures, IPs, timestamps)
- **Use allowlists instead of blocklists** when possible
- **Fail securely** with appropriate error messages
- **Rate limit** to prevent abuse

### Error Handling

```python
# Good: Specific, actionable error messages
if not signature:
    raise InvalidSignatureError("Signature cannot be empty")

# Bad: Generic error that reveals internal state
if hmac_result != expected:
    raise Exception(f"HMAC validation failed: got {hmac_result}")
```

## 📖 Documentation

### Documentation Requirements

- **Clear examples** for beginners
- **Security implications** explained
- **Best practices** included
- **Common pitfalls** highlighted

### Documentation Structure

```
docs/
├── security.md        # Security best practices
├── api.md            # API reference
├── examples.md       # Usage examples
└── troubleshooting.md # Common issues
```

## 🚦 Pull Request Process

### Before Submitting

1. **Run all tests** and ensure they pass
2. **Add tests** for new functionality
3. **Update documentation** if needed
4. **Run security checks** and code quality tools
5. **Test examples** to ensure they work

### Pull Request Template

```markdown
## Description
Brief description of changes and motivation.

## Security Impact
Describe any security implications of the changes.

## Testing
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Security edge cases tested
- [ ] Examples updated and tested

## Documentation
- [ ] API documentation updated
- [ ] Examples updated
- [ ] Security implications documented

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Security considerations addressed
```

### Review Process

1. **Automated checks** must pass (tests, linting, security scans)
2. **Security review** by maintainers
3. **Code review** focusing on quality and correctness
4. **Documentation review** for clarity and completeness

## 🐛 Bug Reports

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities. Instead:

1. **Email**: security@webhook-guardian.dev
2. **Include**: Detailed description, reproduction steps, potential impact
3. **Wait**: For acknowledgment before public disclosure

### Regular Bug Reports

Use the GitHub issue template:

```markdown
## Bug Description
Clear description of what the bug is.

## Reproduction Steps
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Environment
- Python version:
- Webhook Guardian version:
- Operating System:

## Security Impact
Any potential security implications.
```

## 💡 Feature Requests

### Guidelines

- **Security-focused**: Features should enhance security
- **Backward compatible**: Don't break existing functionality
- **Well-motivated**: Clear use case and benefits
- **Simple**: Prefer simple, focused features

### Feature Request Template

```markdown
## Feature Description
Clear description of the proposed feature.

## Use Case
Why is this feature needed? What problem does it solve?

## Security Considerations
How does this feature impact security?

## Implementation Ideas
Any thoughts on how this could be implemented?

## Examples
Code examples showing how the feature would be used.
```

## 📞 Getting Help

- **Documentation**: Check the docs first
- **Discussions**: Use GitHub Discussions for questions
- **Issues**: Create an issue for bugs or feature requests
- **Email**: security@webhook-guardian.dev for security concerns

## 🏆 Recognition

Contributors are recognized in:

- **CONTRIBUTORS.md** file
- **Release notes** for significant contributions
- **Documentation** for major features

Thank you for helping make webhook security better for everyone! 🛡️
