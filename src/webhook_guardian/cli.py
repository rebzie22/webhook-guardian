"""Command-line interface for webhook-guardian."""

import argparse
import json
import sys
from typing import Dict, Any

from . import WebhookValidator, WebhookGuardian


def validate_signature_command(args) -> int:
    """Handle signature validation command."""
    try:
        validator = WebhookValidator(args.secret)
        is_valid = validator.verify_signature(args.payload, args.signature)
        
        result = {
            "valid": is_valid,
            "payload": args.payload,
            "signature": args.signature
        }
        
        print(json.dumps(result, indent=2))
        return 0 if is_valid else 1
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def validate_webhook_command(args) -> int:
    """Handle full webhook validation command."""
    try:
        config = {}
        if args.config:
            with open(args.config, 'r') as f:
                config = json.load(f)
        
        guardian = WebhookGuardian(
            secret=args.secret,
            allowed_ips=config.get('allowed_ips'),
            max_payload_size=config.get('max_payload_size'),
            rate_limit=config.get('rate_limit')
        )
        
        result = guardian.validate_webhook(
            payload=args.payload,
            signature=args.signature,
            client_ip=args.client_ip,
            timestamp=args.timestamp
        )
        
        output = {
            "valid": result.is_valid,
            "error": result.error_message,
            "details": result.validation_details
        }
        
        print(json.dumps(output, indent=2))
        return 0 if result.is_valid else 1
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Webhook Guardian - Secure webhook validation tool"
    )
    parser.add_argument("--version", action="version", version="webhook-guardian 0.1.0")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Signature validation command
    sig_parser = subparsers.add_parser("validate-signature", help="Validate webhook signature")
    sig_parser.add_argument("--secret", required=True, help="Secret key for HMAC validation")
    sig_parser.add_argument("--payload", required=True, help="Webhook payload")
    sig_parser.add_argument("--signature", required=True, help="Webhook signature")
    sig_parser.set_defaults(func=validate_signature_command)
    
    # Full webhook validation command
    webhook_parser = subparsers.add_parser("validate-webhook", help="Full webhook validation")
    webhook_parser.add_argument("--secret", required=True, help="Secret key for HMAC validation")
    webhook_parser.add_argument("--payload", required=True, help="Webhook payload")
    webhook_parser.add_argument("--signature", required=True, help="Webhook signature")
    webhook_parser.add_argument("--client-ip", required=True, help="Client IP address")
    webhook_parser.add_argument("--timestamp", help="Webhook timestamp")
    webhook_parser.add_argument("--config", help="JSON config file with security settings")
    webhook_parser.set_defaults(func=validate_webhook_command)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
