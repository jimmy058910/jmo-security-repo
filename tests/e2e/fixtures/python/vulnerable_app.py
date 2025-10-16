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
