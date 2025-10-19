#!/usr/bin/env bash
# Test script for Resend email integration
# Usage: ./scripts/core/test_email.sh your@email.com

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <test_email>"
  echo ""
  echo "Example: $0 test@example.com"
  echo ""
  echo "Make sure to set RESEND_API_KEY first:"
  echo "  export RESEND_API_KEY='re_...'"
  exit 1
fi

TEST_EMAIL="$1"

if [ -z "$RESEND_API_KEY" ]; then
  echo "❌ Error: RESEND_API_KEY environment variable not set"
  echo ""
  echo "Get your API key from: https://resend.com/api-keys"
  echo "Then run: export RESEND_API_KEY='re_...'"
  exit 1
fi

echo "Testing Resend email integration..."
echo "Sending test email to: $TEST_EMAIL"
echo ""

# Install resend if not already installed
if ! python3 -c "import resend" 2>/dev/null; then
  echo "Installing resend package..."
  pip install resend
fi

# Test the email service
python3 scripts/core/email_service.py "$TEST_EMAIL"
