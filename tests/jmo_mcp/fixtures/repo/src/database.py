"""Database access layer with SQL injection vulnerability"""

import sqlite3


def get_user_by_id(user_id):
    """Fetch user from database by ID.

    Args:
        user_id: User ID from request parameters

    Returns:
        User record or None
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # VULNERABLE: SQL injection via f-string formatting (line 15)
    query = f"SELECT * FROM users WHERE id = {user_id}"

    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()

    return result


def safe_get_user_by_id(user_id):
    """Safe version using parameterized queries"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    result = cursor.fetchone()
    conn.close()

    return result
