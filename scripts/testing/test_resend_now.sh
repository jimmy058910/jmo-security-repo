#!/usr/bin/env bash
# Quick test script for Resend email integration

set -e

echo "🧪 Testing Resend Email Integration"
echo "===================================="
echo ""

# Check if API key is set
if [ -z "$RESEND_API_KEY" ]; then
  echo "❌ ERROR: RESEND_API_KEY environment variable not set"
  echo ""
  echo "Please set your Resend API key:"
  echo "  export RESEND_API_KEY='your-api-key-here'"
  echo ""
  echo "Or add to .env file:"
  echo "  echo 'RESEND_API_KEY=your-api-key-here' >> .env"
  echo "  source .env"
  exit 1
else
  echo "✅ API key found in environment"
fi

echo ""
echo "Installing resend package if needed..."
pip install -q resend

echo ""
echo "Testing email to: jimmy058910@gmail.com"
echo ""

# Run the test
python3 scripts/core/email_service.py jimmy058910@gmail.com

echo ""
echo "===================================="
echo "If you see '✅ Email sent successfully!' above,"
echo "check your inbox at jimmy058910@gmail.com"
echo "(Don't forget to check spam folder!)"
