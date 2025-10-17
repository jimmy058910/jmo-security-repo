#!/usr/bin/env bash
# Quick test script for Resend email integration

set -e

echo "🧪 Testing Resend Email Integration"
echo "===================================="
echo ""

# Check if API key is set
if [ -z "$RESEND_API_KEY" ]; then
    echo "Setting your API key from the chat..."
    export RESEND_API_KEY="re_iDAQB1Gt_LL9goU5s7zKuBXejJVARuacp"
    echo "✅ API key set"
else
    echo "✅ API key already set"
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
