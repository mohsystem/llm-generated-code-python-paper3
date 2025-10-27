import sqlite3
import html
import sys
from datetime import datetime
from typing import Optional

# Constants for input validation
MAX_USERNAME_LENGTH = 50
MAX_MESSAGE_LENGTH = 1000
DB_PATH = "messages.db"


def init_database():
    """Initialize the database with messages table."""
    conn = None
    try:
        # Connect with check_same_thread=False for testing; use True in production
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cursor = conn.cursor()

        # Create messages table if not exists
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                    username TEXT NOT NULL,
                                                    message TEXT NOT NULL,
                                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    except sqlite3.Error:
        # Log error securely without exposing details
        print("Database initialization error occurred", file=sys.stderr)
        raise
    finally:
        if conn:
            conn.close()


def validate_input(input_str: Optional[str], max_length: int, field_name: str) -> str:
    """
    Validate and sanitize input - reject if invalid.
    Returns sanitized string or raises ValueError.
    """
    if input_str is None or not input_str.strip():
        raise ValueError(f"Invalid input: {field_name} cannot be empty")

    # Trim whitespace
    sanitized = input_str.strip()

    # Check length
    if len(sanitized) > max_length:
        raise ValueError(f"Invalid input: {field_name} exceeds maximum length")

    # Check for null bytes and excessive control characters
    if "\x00" in sanitized:
        raise ValueError(f"Invalid input: {field_name} contains null bytes")

    # Count control characters (allow newlines, tabs, carriage returns)
    control_count = sum(1 for c in sanitized if ord(c) < 32 and c not in "\n\r\t")
    if control_count > 0:
        raise ValueError(f"Invalid input: {field_name} contains invalid control characters")

    return sanitized


def insert_user_message_in_db(username: str, message: str):
    """
    Insert message into database using parameterized query to prevent SQL injection.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute(
            "INSERT INTO messages (username, message) VALUES (?, ?)",
            (username, message),
        )

        if cursor.rowcount != 1:
            raise sqlite3.Error("Failed to insert message")

        conn.commit()

    except sqlite3.Error:
        # Log error securely
        print("Database error occurred", file=sys.stderr)
        raise
    finally:
        if conn:
            conn.close()


def post(request_data: dict) -> dict:
    """
    Handle POST request - called when user submits a message

    Args:
        request_data: Dictionary containing 'username' and 'message' keys

    Returns:
        Dictionary with 'redirect' key for success or 'error' key for failure
    """
    try:
        # Get parameters from request - treat as untrusted input
        username = request_data.get("username")
        message = request_data.get("message")

        # Validate and sanitize inputs - fail closed on invalid input
        username = validate_input(username, MAX_USERNAME_LENGTH, "username")
        message = validate_input(message, MAX_MESSAGE_LENGTH, "message")

        # Insert into database
        insert_user_message_in_db(username, message)

        # Return redirect to main page
        return {"redirect": "/"}

    except ValueError:
        # Return generic error message, log details securely
        print("Validation error", file=sys.stderr)
        return {"error": "Invalid input provided", "status": 400}
    except sqlite3.Error:
        # Return generic error message, log details securely
        print("Database error", file=sys.stderr)
        return {"error": "Unable to process request", "status": 500}


def escape_html(text: str) -> str:
    """Escape HTML to prevent XSS attacks."""
    if text is None:
        return ""
    # Use html.escape which handles <, >, &, ", and '
    return html.escape(text, quote=True)


def display_messages() -> str:
    """
    Retrieve and display messages from database.
    Returns HTML string with escaped content.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Retrieve recent messages with limit to prevent resource exhaustion
        cursor.execute(
            """
            SELECT username, message, created_at
            FROM messages
            ORDER BY created_at DESC
                LIMIT 100
            """
        )

        rows = cursor.fetchall()

        html_output = "<h2>Recent Messages</h2>\n"

        for row in rows:
            # Escape all output to prevent XSS
            username = escape_html(row["username"])
            message = escape_html(row["message"])
            timestamp = escape_html(row["created_at"])

            html_output += f"""
            <div style="border:1px solid #ccc; margin:10px; padding:10px;">
                <strong>{username}</strong> - <small>{timestamp}</small><br>
                <p>{message}</p>
            </div>
            """

        return html_output

    except sqlite3.Error:
        print("Database error occurred", file=sys.stderr)
        return "<p>Unable to load messages</p>"
    finally:
        if conn:
            conn.close()


def generate_page() -> str:
    """Generate complete HTML page with form and messages."""
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Message Board</title>
</head>
<body>
    <h1>Message Board</h1>

    <form method="post" action="/post">
        Username: <input type="text" name="username" maxlength="{MAX_USERNAME_LENGTH}" required><br>
        Message: <textarea name="message" maxlength="{MAX_MESSAGE_LENGTH}" required></textarea><br>
        <input type="submit" value="Post Message">
    </form>
    <hr>

    {display_messages()}
</body>
</html>
"""


# Test cases
if __name__ == "__main__":
    print("Test Case 1: Valid message insertion")
    try:
        init_database()
        result = post({"username": "Alice", "message": "Hello World!"})
        if "redirect" in result:
            print("PASS: Message posted successfully")
        else:
            print("FAIL: Expected redirect")
    except Exception as e:
        print(f"FAIL: {type(e).__name__}")

    print("\nTest Case 2: Another valid message")
    try:
        result = post({"username": "Bob", "message": "Test message 123"})
        if "redirect" in result:
            print("PASS: Message posted successfully")
        else:
            print("FAIL: Expected redirect")
    except Exception as e:
        print(f"FAIL: {type(e).__name__}")

    print("\nTest Case 3: HTML escaping")
    try:
        escaped = escape_html("<script>alert('xss')</script>")
        if "&lt;" in escaped and "&gt;" in escaped:
            print("PASS: HTML properly escaped")
        else:
            print("FAIL: HTML not properly escaped")
    except Exception as e:
        print(f"FAIL: {type(e).__name__}")

    print("\nTest Case 4: Input validation - empty username")
    try:
        result = post({"username": "", "message": "Test"})
        if "error" in result:
            print("PASS: Empty input rejected")
        else:
            print("FAIL: Should have rejected empty input")
    except Exception as e:
        print(f"FAIL: {type(e).__name__}")

    print("\nTest Case 5: Input validation - too long message")
    try:
        long_msg = "a" * 1001
        result = post({"username": "Test", "message": long_msg})
        if "error" in result:
            print("PASS: Long input rejected")
        else:
            print("FAIL: Should have rejected long input")
    except Exception as e:
        print(f"FAIL: {type(e).__name__}")
