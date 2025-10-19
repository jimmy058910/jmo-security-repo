#!/usr/bin/env bash
# Setup test fixtures for comprehensive E2E tests
# Creates realistic test files with known security issues

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Setting up test fixtures in $SCRIPT_DIR"

# ============================================================================
# IaC Fixtures
# ============================================================================

mkdir -p "$SCRIPT_DIR/iac"

# AWS S3 public bucket (CIS AWS Foundations Benchmark violations)
cat >"$SCRIPT_DIR/iac/aws-s3-public.tf" <<'EOF'
# Terraform configuration with known security issues
# Used for testing IaC scanning capabilities

resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-test-bucket"

  # CIS 2.1.5: S3 bucket should not be public
  # OWASP A05:2021 - Security Misconfiguration
  acl    = "public-read"

  tags = {
    Environment = "test"
    Purpose     = "security-testing"
  }
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all_traffic"
  description = "Security group allowing all inbound traffic"

  # CIS 4.1: Security groups should not allow 0.0.0.0/0 ingress
  # OWASP A01:2021 - Broken Access Control
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all inbound traffic"
  }

  # CIS 4.2: Security groups should restrict SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "default" {
  identifier           = "test-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20

  # CIS 2.3.1: RDS instances should have encryption enabled
  storage_encrypted    = false

  # CIS 2.3.2: RDS instances should not be publicly accessible
  publicly_accessible  = true

  # Hardcoded credentials (CWE-798)
  username             = "admin"
  password             = "SuperSecret123!"

  skip_final_snapshot  = true
}

resource "aws_iam_policy" "overly_permissive" {
  name        = "overly-permissive-policy"
  description = "Policy with overly permissive actions"

  # CIS 1.16: IAM policies should not allow full "*:*" administrative privileges
  # OWASP A01:2021 - Broken Access Control
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
EOF

# Kubernetes privileged pod (CIS Kubernetes Benchmark violations)
cat >"$SCRIPT_DIR/iac/k8s-privileged-pod.yaml" <<'EOF'
# Kubernetes manifest with known security issues
# Used for testing K8s security scanning

apiVersion: v1
kind: Pod
metadata:
  name: privileged-test-pod
  labels:
    app: insecure-app
    environment: test
spec:
  # CIS 5.2.1: Minimize admission of privileged containers
  containers:
  - name: app-container
    image: nginx:latest  # No image pinning (CIS 5.1.1)

    securityContext:
      privileged: true    # CIS 5.2.1 violation
      runAsUser: 0        # CIS 5.2.6: Run as non-root user
      allowPrivilegeEscalation: true  # CIS 5.2.5
      readOnlyRootFilesystem: false   # CIS 5.2.9

    resources:
      # No resource limits set (CIS 5.2.13)
      requests:
        memory: "64Mi"
        cpu: "250m"

    # CIS 5.7.3: Apply security context to containers
    # Missing: runAsNonRoot, capabilities drop, etc.

  # No network policies defined (CIS 5.3.2)
  # No pod security policy (CIS 5.2.0)

  hostNetwork: true     # CIS 5.2.4: Do not use host network
  hostPID: true         # CIS 5.2.2: Do not use host PID
  hostIPC: true         # CIS 5.2.3: Do not use host IPC

  volumes:
  - name: host-root
    hostPath:
      path: /           # CIS 5.2.8: Minimize mounting host volumes
      type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: insecure-service
spec:
  type: LoadBalancer  # Exposed to internet without authentication
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: insecure-app
EOF

# Docker bad practices
cat >"$SCRIPT_DIR/iac/Dockerfile.bad" <<'EOF'
# Dockerfile with known security issues
# Used for testing Hadolint scanning

# DL3006: Always tag the version of an image explicitly
FROM ubuntu:latest

# DL3009: Delete the apt-get lists after installing
# DL3008: Pin versions in apt-get install
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat

# DL3020: Use COPY instead of ADD for files
ADD http://example.com/big-file.tar.gz /tmp/

# CIS 4.1: Create a user for the container
# Running as root (implicit)

# DL3045: Use --no-cache-dir with pip
RUN pip install requests

# DL3025: Use JSON format for CMD and ENTRYPOINT
ENTRYPOINT curl http://example.com

# Hardcoded secrets (CWE-798)
ENV API_KEY="sk-1234567890abcdef"
ENV DATABASE_PASSWORD="SuperSecret123!"

# DL3000: Use absolute WORKDIR
WORKDIR app

# CIS 4.7: Do not store secrets in environment variables
# Exposed port without documentation
EXPOSE 8080

# No HEALTHCHECK instruction (CIS 4.6)
EOF

# Docker Compose with issues
cat >"$SCRIPT_DIR/iac/docker-compose.insecure.yml" <<'EOF'
version: '3.8'

services:
  web:
    image: nginx:latest  # No version pinning
    ports:
      - "80:80"  # Exposed to all interfaces
    environment:
      - API_KEY=hardcoded-key-12345  # Hardcoded secret
    privileged: true  # Unnecessary privileges
    network_mode: host  # Using host network

  db:
    image: postgres:latest
    ports:
      - "5432:5432"  # Database exposed externally
    environment:
      - POSTGRES_PASSWORD=weak123  # Weak password
      - POSTGRES_HOST_AUTH_METHOD=trust  # No authentication
    volumes:
      - /:/host-root  # Mounting host root
EOF

echo "✓ Created IaC fixtures"

# ============================================================================
# Python fixtures (for SAST testing)
# ============================================================================

mkdir -p "$SCRIPT_DIR/python"

cat >"$SCRIPT_DIR/python/vulnerable_app.py" <<'EOF'
# Python application with known security vulnerabilities
# Used for testing Bandit and Semgrep

import os
import pickle
import subprocess
import yaml
from flask import Flask, request

app = Flask(__name__)

# CWE-798: Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "SuperSecret123!"

# CWE-327: Use of weak cryptographic algorithm
import hashlib
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# CWE-89: SQL Injection
import sqlite3
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

# CWE-78: OS Command Injection
def run_command(user_input):
    # Command injection vulnerability
    os.system(f"ls {user_input}")
    subprocess.call(f"ping {user_input}", shell=True)

# CWE-502: Deserialization of Untrusted Data
def load_data(serialized_data):
    # Pickle deserialization vulnerability
    return pickle.loads(serialized_data)

# CWE-611: XXE vulnerability
def parse_xml(xml_string):
    from xml.etree.ElementTree import fromstring
    return fromstring(xml_string)

# CWE-22: Path Traversal
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    # Path traversal vulnerability
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

# CWE-79: Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    query = request.args.get('q')
    # XSS vulnerability (reflected)
    return f"<html><body>Search results for: {query}</body></html>"

# CWE-732: Incorrect Permission Assignment
def create_sensitive_file():
    with open('/tmp/sensitive.txt', 'w') as f:
        f.write("Secret data")
    os.chmod('/tmp/sensitive.txt', 0o777)  # World-writable

# CWE-330: Use of Insufficiently Random Values
import random
def generate_token():
    return random.randint(1000, 9999)

# CWE-601: Open Redirect
@app.route('/redirect')
def redirect_user():
    url = request.args.get('url')
    # Open redirect vulnerability
    return redirect(url)

# CWE-918: Server-Side Request Forgery (SSRF)
import requests
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # SSRF vulnerability
    response = requests.get(url)
    return response.text

if __name__ == '__main__':
    # CWE-489: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0')
EOF

echo "✓ Created Python fixtures"

# ============================================================================
# JavaScript/Node.js fixtures
# ============================================================================

mkdir -p "$SCRIPT_DIR/javascript"

cat >"$SCRIPT_DIR/javascript/package.json" <<'EOF'
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "description": "Test app with known vulnerabilities",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.4",
    "jquery": "2.1.4",
    "moment": "2.19.1",
    "axios": "0.18.0"
  }
}
EOF

cat >"$SCRIPT_DIR/javascript/vulnerable_app.js" <<'EOF'
// Node.js application with known security vulnerabilities
const express = require('express');
const exec = require('child_process').exec;
const app = express();

// CWE-798: Hardcoded credentials
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'SuperSecret123!';

// CWE-78: Command Injection
app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    exec(`ls ${cmd}`, (err, stdout) => {
        res.send(stdout);
    });
});

// CWE-73: External Control of File Name or Path
app.get('/file', (req, res) => {
    const filename = req.query.name;
    res.sendFile(filename);
});

// CWE-079: XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<html><body>Results for: ${query}</body></html>`);
});

// CWE-327: Weak crypto
const crypto = require('crypto');
function weakEncrypt(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// CWE-89: SQL Injection (conceptual)
const sqlite3 = require('sqlite3');
app.get('/user', (req, res) => {
    const db = new sqlite3.Database(':memory:');
    const username = req.query.username;
    // SQL injection vulnerability
    db.all(`SELECT * FROM users WHERE name = '${username}'`, (err, rows) => {
        res.json(rows);
    });
});

// CWE-601: Open Redirect
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url);
});

// Insecure server configuration
app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on port 3000');
});
EOF

echo "✓ Created JavaScript fixtures"

# ============================================================================
# Configuration files
# ============================================================================

mkdir -p "$SCRIPT_DIR/configs"

cat >"$SCRIPT_DIR/configs/.env.example" <<'EOF'
# Example .env file with hardcoded secrets (for testing detection)
API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz
DATABASE_URL=postgresql://admin:SuperSecret123!@localhost:5432/mydb
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_test_FakeKeyForTestingPurposesOnly123456
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX
EOF

cat >"$SCRIPT_DIR/configs/secrets.yaml" <<'EOF'
# YAML config with secrets (for testing detection)
database:
  host: localhost
  port: 5432
  username: admin
  password: SuperSecret123!

api:
  key: sk-1234567890abcdef
  secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCY

aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region: us-east-1
EOF

echo "✓ Created configuration fixtures"

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "=========================================="
echo "Test Fixtures Setup Complete"
echo "=========================================="
echo "Fixture directory: $SCRIPT_DIR"
echo ""
echo "Created fixtures:"
echo "  IaC:"
echo "    - aws-s3-public.tf (Terraform with CIS violations)"
echo "    - k8s-privileged-pod.yaml (K8s with security issues)"
echo "    - Dockerfile.bad (Docker with Hadolint violations)"
echo "    - docker-compose.insecure.yml (Docker Compose issues)"
echo "  Python:"
echo "    - vulnerable_app.py (Flask app with OWASP Top 10)"
echo "  JavaScript:"
echo "    - package.json (Outdated vulnerable dependencies)"
echo "    - vulnerable_app.js (Express app with OWASP Top 10)"
echo "  Configs:"
echo "    - .env.example (Hardcoded secrets)"
echo "    - secrets.yaml (API keys and credentials)"
echo ""
echo "These fixtures contain intentional security issues for testing purposes."
echo "Do NOT use in production or commit real secrets!"
