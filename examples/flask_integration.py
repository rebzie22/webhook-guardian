"""
Flask web application example showing webhook-guardian integration.

This example demonstrates how to integrate webhook-guardian into a real
Flask web application for secure webhook handling.
"""

# Note: This requires Flask to be installed
# pip install flask

from flask import Flask, request, jsonify
import json
import logging

# Import webhook-guardian (install with: pip install webhook-guardian)
from webhook_guardian import WebhookGuardian


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configure webhook security
webhook_guardian = WebhookGuardian(
    secret="your-production-webhook-secret",
    tolerance_seconds=300,
    allowed_ips=[
        "192.30.252.0/22",    # GitHub webhook IPs (example)
        "185.199.108.0/22",   # GitHub webhook IPs (example)
        # Add your webhook provider's IP ranges
    ],
    max_payload_size=1024 * 1024,  # 1MB limit
    rate_limit={
        "requests": 1000,     # 1000 requests
        "window": 3600        # per hour
    },
    enable_logging=True
)


@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    """Handle GitHub webhooks securely."""
    
    # Get request data
    payload = request.get_data(as_text=True)
    signature = request.headers.get('X-Hub-Signature-256', '')
    client_ip = get_client_ip(request)
    timestamp = request.headers.get('X-GitHub-Delivery-Timestamp')
    
    # Validate the webhook
    result = webhook_guardian.validate_webhook(
        payload=payload,
        signature=signature,
        client_ip=client_ip,
        timestamp=timestamp
    )
    
    if not result.is_valid:
        logger.warning(f"Invalid webhook from {client_ip}: {result.error_message}")
        return jsonify({
            "error": "Invalid webhook",
            "details": result.error_message
        }), 401
    
    logger.info(f"Valid webhook received from {client_ip}")
    
    # Process the webhook
    try:
        webhook_data = json.loads(payload)
        event_type = request.headers.get('X-GitHub-Event')
        
        # Route to specific handlers
        if event_type == 'push':
            handle_push_event(webhook_data)
        elif event_type == 'pull_request':
            handle_pull_request_event(webhook_data)
        elif event_type == 'issues':
            handle_issues_event(webhook_data)
        else:
            logger.info(f"Unhandled event type: {event_type}")
        
        return jsonify({"status": "success"}), 200
        
    except json.JSONDecodeError:
        logger.error("Invalid JSON in webhook payload")
        return jsonify({"error": "Invalid JSON"}), 400
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return jsonify({"error": "Processing failed"}), 500


@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhooks securely."""
    
    payload = request.get_data(as_text=True)
    signature = request.headers.get('Stripe-Signature', '')
    client_ip = get_client_ip(request)
    
    # Note: Stripe uses a different signature format
    # You might need to adapt the signature validation for Stripe's format
    
    result = webhook_guardian.validate_webhook(
        payload=payload,
        signature=signature,
        client_ip=client_ip
    )
    
    if not result.is_valid:
        logger.warning(f"Invalid Stripe webhook from {client_ip}")
        return jsonify({"error": "Invalid webhook"}), 401
    
    try:
        webhook_data = json.loads(payload)
        event_type = webhook_data.get('type')
        
        # Handle Stripe events
        if event_type == 'payment_intent.succeeded':
            handle_payment_success(webhook_data)
        elif event_type == 'payment_intent.payment_failed':
            handle_payment_failure(webhook_data)
        elif event_type == 'customer.subscription.created':
            handle_subscription_created(webhook_data)
        else:
            logger.info(f"Unhandled Stripe event: {event_type}")
        
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        logger.error(f"Error processing Stripe webhook: {e}")
        return jsonify({"error": "Processing failed"}), 500


@app.route('/webhook/status', methods=['GET'])
def webhook_status():
    """Get webhook system status and rate limit information."""
    
    client_ip = get_client_ip(request)
    rate_limit_status = webhook_guardian.get_rate_limit_status(client_ip)
    
    return jsonify({
        "status": "operational",
        "rate_limit": rate_limit_status,
        "security_features": {
            "signature_validation": True,
            "timestamp_validation": True,
            "ip_whitelisting": len(webhook_guardian.allowed_networks) > 0,
            "rate_limiting": webhook_guardian.rate_limiter is not None,
            "payload_size_limits": webhook_guardian.max_payload_size is not None
        }
    })


def get_client_ip(request):
    """Get the real client IP address (handles proxies)."""
    
    # Check for forwarded headers (when behind reverse proxy)
    forwarded_ips = request.headers.getlist("X-Forwarded-For")
    if forwarded_ips:
        return forwarded_ips[0].split(',')[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.remote_addr


# Event handlers
def handle_push_event(data):
    """Handle GitHub push events."""
    repository = data.get('repository', {}).get('name')
    pusher = data.get('pusher', {}).get('name')
    commits = len(data.get('commits', []))
    
    logger.info(f"Push to {repository} by {pusher}: {commits} commits")
    
    # Add your CI/CD logic here
    # - Trigger builds
    # - Run tests
    # - Deploy to staging
    

def handle_pull_request_event(data):
    """Handle GitHub pull request events."""
    action = data.get('action')
    pr_number = data.get('number')
    repository = data.get('repository', {}).get('name')
    
    logger.info(f"PR #{pr_number} {action} in {repository}")
    
    # Add your PR automation here
    # - Run code reviews
    # - Update status checks
    # - Send notifications


def handle_issues_event(data):
    """Handle GitHub issues events."""
    action = data.get('action')
    issue_number = data.get('issue', {}).get('number')
    
    logger.info(f"Issue #{issue_number} {action}")
    
    # Add your issue automation here
    # - Auto-assign labels
    # - Create Jira tickets
    # - Send notifications


def handle_payment_success(data):
    """Handle successful payment from Stripe."""
    payment_intent = data.get('data', {}).get('object', {})
    amount = payment_intent.get('amount')
    customer = payment_intent.get('customer')
    
    logger.info(f"Payment succeeded: ${amount/100:.2f} for customer {customer}")
    
    # Add your payment processing logic here
    # - Update order status
    # - Send confirmation emails
    # - Grant access to products


def handle_payment_failure(data):
    """Handle failed payment from Stripe."""
    payment_intent = data.get('data', {}).get('object', {})
    customer = payment_intent.get('customer')
    failure_reason = payment_intent.get('last_payment_error', {}).get('message')
    
    logger.info(f"Payment failed for customer {customer}: {failure_reason}")
    
    # Add your failure handling logic here
    # - Send failure notifications
    # - Retry payment
    # - Update subscription status


def handle_subscription_created(data):
    """Handle new subscription from Stripe."""
    subscription = data.get('data', {}).get('object', {})
    customer = subscription.get('customer')
    plan = subscription.get('items', {}).get('data', [{}])[0].get('price', {}).get('id')
    
    logger.info(f"New subscription created for customer {customer}: plan {plan}")
    
    # Add your subscription logic here
    # - Activate premium features
    # - Send welcome emails
    # - Update user permissions


if __name__ == '__main__':
    # Development server
    print("🚀 Starting Flask webhook server with security features...")
    print("📋 Available endpoints:")
    print("  POST /webhook/github - GitHub webhooks")
    print("  POST /webhook/stripe - Stripe webhooks") 
    print("  GET  /webhook/status - System status")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
