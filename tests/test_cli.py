"""Tests for the CLI module."""

import pytest
import json
import sys
from unittest.mock import patch, mock_open
from io import StringIO

from webhook_guardian.cli import (
    validate_signature_command,
    validate_webhook_command,
    main
)


class TestCLI:
    """Test cases for CLI functionality."""
    
    def test_validate_signature_command_valid(self, capsys):
        """Test CLI signature validation with valid signature."""
        # Mock arguments
        class MockArgs:
            secret = "test-secret"
            payload = '{"test": "data"}'
            signature = "sha256=84c600d9e8c6b5b4d0ad3e0a7e6b8f5a2c4b2e9d3f1a5c8b7e6d9a2b1c4e3f2a1"
        
        args = MockArgs()
        result = validate_signature_command(args)
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        
        assert result == 1  # Invalid signature (expected)
        assert output["valid"] is False
        assert output["payload"] == '{"test": "data"}'
    
    def test_validate_signature_command_error(self, capsys):
        """Test CLI signature validation with error."""
        class MockArgs:
            secret = ""  # Empty secret should cause error
            payload = '{"test": "data"}'
            signature = "sha256=invalid"
        
        args = MockArgs()
        result = validate_signature_command(args)
        
        captured = capsys.readouterr()
        assert result == 1
        assert "Error:" in captured.err
    
    def test_validate_webhook_command_no_config(self, capsys):
        """Test CLI webhook validation without config file."""
        class MockArgs:
            secret = "test-secret"
            payload = '{"test": "data"}'
            signature = "sha256=invalid"
            client_ip = "192.168.1.100"
            timestamp = None
            config = None
        
        args = MockArgs()
        result = validate_webhook_command(args)
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        
        assert result == 1  # Invalid signature
        assert output["valid"] is False
        assert output["error"] is not None
    
    @patch("builtins.open", new_callable=mock_open, read_data='{"allowed_ips": ["192.168.1.0/24"]}')
    def test_validate_webhook_command_with_config(self, mock_file, capsys):
        """Test CLI webhook validation with config file."""
        class MockArgs:
            secret = "test-secret"
            payload = '{"test": "data"}'
            signature = "sha256=invalid"
            client_ip = "192.168.1.100"
            timestamp = None
            config = "config.json"
        
        args = MockArgs()
        result = validate_webhook_command(args)
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        
        assert result == 1  # Invalid signature
        assert output["valid"] is False
        mock_file.assert_called_once_with("config.json", 'r')
    
    def test_validate_webhook_command_error(self, capsys):
        """Test CLI webhook validation with error."""
        class MockArgs:
            secret = ""  # Empty secret should cause error
            payload = '{"test": "data"}'
            signature = "sha256=invalid"
            client_ip = "192.168.1.100"
            timestamp = None
            config = None
        
        args = MockArgs()
        result = validate_webhook_command(args)
        
        captured = capsys.readouterr()
        assert result == 1
        assert "Error:" in captured.err
    
    @patch('sys.argv', ['webhook-guardian', '--version'])
    def test_main_version(self, capsys):
        """Test CLI version command."""
        with pytest.raises(SystemExit) as exc_info:
            main()
        
        # argparse exits with code 0 for --version
        assert exc_info.value.code == 0
    
    @patch('sys.argv', ['webhook-guardian'])
    def test_main_no_command(self, capsys):
        """Test CLI with no command shows help."""
        result = main()
        assert result == 1
    
    @patch('sys.argv', [
        'webhook-guardian', 
        'validate-signature',
        '--secret', 'test-secret',
        '--payload', '{"test": "data"}',
        '--signature', 'sha256=invalid'
    ])
    def test_main_validate_signature(self, capsys):
        """Test CLI main function with validate-signature command."""
        result = main()
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        
        assert result == 1  # Invalid signature
        assert output["valid"] is False
    
    @patch('sys.argv', [
        'webhook-guardian',
        'validate-webhook',
        '--secret', 'test-secret',
        '--payload', '{"test": "data"}',
        '--signature', 'sha256=invalid',
        '--client-ip', '192.168.1.100'
    ])
    def test_main_validate_webhook(self, capsys):
        """Test CLI main function with validate-webhook command."""
        result = main()
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        
        assert result == 1  # Invalid signature
        assert output["valid"] is False
        assert output["error"] is not None


class TestCLIIntegration:
    """Integration tests for CLI functionality."""
    
    def test_valid_signature_flow(self, capsys):
        """Test complete valid signature validation flow."""
        from webhook_guardian import WebhookValidator
        
        # Generate a valid signature
        validator = WebhookValidator("test-secret")
        test_payload = '{"event": "test", "data": {"id": 123}}'
        valid_signature = validator._compute_signature(test_payload)
        
        class MockArgs:
            secret = "test-secret"
            payload = test_payload
            signature = valid_signature
        
        args = MockArgs()
        result = validate_signature_command(args)
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        
        assert result == 0  # Success
        assert output["valid"] is True
        assert output["payload"] == test_payload
        assert output["signature"] == valid_signature
    
    def test_valid_webhook_flow(self, capsys):
        """Test complete valid webhook validation flow."""
        from webhook_guardian import WebhookValidator
        
        # Generate a valid signature
        validator = WebhookValidator("test-secret")
        test_payload = '{"event": "payment.success", "amount": 100}'
        valid_signature = validator._compute_signature(test_payload)
        
        class MockArgs:
            secret = "test-secret"
            payload = test_payload
            signature = valid_signature
            client_ip = "192.168.1.100"
            timestamp = None
            config = None
        
        args = MockArgs()
        result = validate_webhook_command(args)
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        
        assert result == 0  # Success
        assert output["valid"] is True
        assert output["error"] is None
        assert "details" in output
