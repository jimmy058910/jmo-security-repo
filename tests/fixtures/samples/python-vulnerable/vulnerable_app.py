#!/usr/bin/env python3
"""
Sample vulnerable Python code for golden test fixture generation.

This file contains INTENTIONAL security issues that will be detected by:
- Bandit (Python security linter)
- Semgrep (multi-language SAST)

DO NOT use this code in production - it exists only for testing.
"""

import hashlib
import pickle
import subprocess


# B101: assert_used - Assert statements can be disabled in production
def check_admin(user):
    assert user.is_admin, "User must be admin"
    return True


# B301: pickle - Arbitrary code execution via pickle deserialization
def load_user_data(data_bytes):
    return pickle.loads(data_bytes)


# B303: md5 - Weak cryptographic hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# B311: random - Insecure random number generator
def generate_token():
    import random

    return random.randint(100000, 999999)


# B602: subprocess_popen_with_shell_equals_true - Command injection
def run_command(user_input):
    subprocess.Popen(f"echo {user_input}", shell=True)


# B608: hardcoded_sql_expressions - SQL injection
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query


# B105: hardcoded_password_string - Hardcoded credentials
DATABASE_PASSWORD = "super_secret_password123"


# B110: try_except_pass - Silent exception handling
def risky_operation():
    try:
        dangerous_action()
    except Exception:
        pass


def dangerous_action():
    raise RuntimeError("Simulated error")


# B104: hardcoded_bind_all_interfaces - Network exposure
def start_server():
    import socket

    sock = socket.socket()
    sock.bind(("0.0.0.0", 8080))
    return sock


if __name__ == "__main__":
    # This code should never run - it's just for static analysis testing
    print("This file is for security testing only")
