#!/bin/bash

# JMo Security Email System Testing Script (WSL-friendly)
# This script helps test all email collection touchpoints

set -e

API_URL="https://jmo-security-subscribe-d1h77tlh1-james-moceris-projects.vercel.app"
REPO_ROOT="/home/jimmy058910/jmo-security-repo"

echo "=============================================="
echo "JMo Security Email System Testing"
echo "=============================================="
echo ""

# Test 1: API Health Check
echo "📊 Test 1: API Health Check"
echo "-------------------------------------------"
curl -s "${API_URL}/api/health" | python3 -m json.tool
echo ""
echo "✅ If you see status: 'ok', the API is working!"
echo ""
read -r -p "Press ENTER to continue to Test 2..."
echo ""

# Test 2: Subscribe Landing Page (WSL Browser)
echo "📧 Test 2: Subscribe Landing Page"
echo "-------------------------------------------"
SUBSCRIBE_PAGE="${REPO_ROOT}/docs/subscribe.html"

echo "Opening subscribe page in Windows browser..."
echo "Path: ${SUBSCRIBE_PAGE}"
echo ""

# WSL method to open in Windows browser
if command -v wslview &>/dev/null; then
  wslview "${SUBSCRIBE_PAGE}"
elif command -v explorer.exe &>/dev/null; then
  explorer.exe "$(wslpath -w "${SUBSCRIBE_PAGE}")"
else
  echo "⚠️  Could not auto-open browser. Please manually open:"
  echo "   Windows path: $(wslpath -w "${SUBSCRIBE_PAGE}")"
fi

echo ""
echo "📝 Manual Steps:"
echo "   1. Enter your real email address in the form"
echo "   2. Click 'Subscribe - It's Free'"
echo "   3. Verify success message appears"
echo "   4. Check your inbox for email from marketing@jmotools.com"
echo ""
read -r -p "Press ENTER after testing the subscribe page..."
echo ""

# Test 3: Dashboard Form
echo "📊 Test 3: Dashboard Form"
echo "-------------------------------------------"

# Check if results directory exists
if [ -d "${REPO_ROOT}/results" ] && [ -f "${REPO_ROOT}/results/summaries/dashboard.html" ]; then
  echo "Found existing dashboard, opening..."
  DASHBOARD="${REPO_ROOT}/results/summaries/dashboard.html"

  if command -v wslview &>/dev/null; then
    wslview "${DASHBOARD}"
  elif command -v explorer.exe &>/dev/null; then
    explorer.exe "$(wslpath -w "${DASHBOARD}")"
  else
    echo "⚠️  Could not auto-open browser. Please manually open:"
    echo "   Windows path: $(wslpath -w "${DASHBOARD}")"
  fi
else
  echo "⚠️  No dashboard found. Let's generate one..."
  echo "Run this command: jmo report ./results"
  echo "Then run: ./test_email_system.sh and skip to this section"
fi

echo ""
echo "📝 Manual Steps:"
echo "   1. Scroll down to the purple email signup section"
echo "   2. Enter your email"
echo "   3. Click 'Subscribe Free'"
echo "   4. Verify success message"
echo ""
read -r -p "Press ENTER after testing the dashboard form..."
echo ""

# Test 4: CLI First-Run Experience
echo "🖥️  Test 4: CLI First-Run Experience"
echo "-------------------------------------------"
echo "This will reset your JMo config to simulate a first-time user"
echo ""
read -r -p "Press ENTER to continue (or Ctrl+C to skip)..."

# Backup existing config if it exists
if [ -f ~/.jmo/config.yml ]; then
  echo "Backing up existing config to ~/.jmo/config.yml.bak"
  cp ~/.jmo/config.yml ~/.jmo/config.yml.bak
  rm ~/.jmo/config.yml
fi

echo ""
echo "Running first scan (this will trigger the welcome prompt)..."
echo ""

# Check if jmo command exists
if ! command -v jmo &>/dev/null; then
  echo "⚠️  'jmo' command not found. You may need to:"
  echo "   1. Install: pip install -e ."
  echo "   2. Or use: python3 scripts/cli/jmo.py scan --repo . --profile fast --results-dir /tmp/test-results"
else
  jmo scan --repo . --profile fast --results-dir /tmp/test-results --human-logs
fi

echo ""
echo "✅ Check if you saw the welcome prompt asking for your email!"
echo ""

# Test 5: Verify Config Saved
if [ -f ~/.jmo/config.yml ]; then
  echo "📁 Test 5: Config File Check"
  echo "-------------------------------------------"
  echo "Config file exists at: ~/.jmo/config.yml"
  echo ""
  echo "Contents:"
  cat ~/.jmo/config.yml
else
  echo "⚠️  No config file found. Did the scan complete?"
fi

echo ""
echo "=============================================="
echo "🎉 Testing Complete!"
echo "=============================================="
echo ""
echo "📋 Summary:"
echo "   • API Health Check: Test manually above"
echo "   • Subscribe Page: Check if email was sent"
echo "   • Dashboard Form: Check if form worked"
echo "   • CLI First-Run: Check if prompt appeared"
echo ""
echo "📧 Check your inbox for:"
echo "   From: JMo Security <marketing@jmotools.com>"
echo "   Subject: Welcome to JMo Security! 🎉"
echo ""
echo "📊 Monitor emails at:"
echo "   Resend Dashboard: https://resend.com/emails"
echo "   Vercel Logs: https://vercel.com/james-moceris-projects/jmo-security-subscribe-api/logs"
echo ""
