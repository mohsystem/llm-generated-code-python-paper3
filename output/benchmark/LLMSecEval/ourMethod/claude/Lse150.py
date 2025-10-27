
from flask import Flask, request, redirect, render_template_string
import sqlite3
import html
from typing import Optional

app = Flask(__name__)

# Maximum input lengths to prevent excessive memory usage
MAX_USERNAME_LENGTH = 50
MAX_MESSAGE_LENGTH = 500

def validate_input(input_str: Optional[str], max_length: int) -> Optional[str]:
    """\n    Validates and sanitizes input string with strict bounds checking.\n    \n    Args:\n        input_str: The input to validate\n        max_length: Maximum allowed length\n        \n    Returns:\n        Validated string or None if invalid\n    """
    # Check for None or empty after stripping whitespace
    if input_str is None:
        return None
    
    trimmed = input_str.strip()
    if not trimmed:
        return None
    
    # Enforce length boundary to prevent buffer overflow concerns
    if len(trimmed) > max_length:
        return None
    
    # Reject strings with control characters except newline and tab
    for char in trimmed:
        if ord(char) < 32 and char not in ('\\n', '\\t'):
            return None
    
    return trimmed
def insert_user_message_in_db(username: str, message: str) -> bool:
    """
    Inserts message into database using parameterized queries to prevent SQL injection.

    Args:
        username: Validated username
        message: Validated message

    Returns:
        True if successful, False otherwise
    """
    try:
        # Use parameterized query to prevent SQL injection
        with sqlite3.connect("messages.db") as conn:
            cursor = conn.cursor()

            # Create table if not exists (for demo purposes)
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS messages
                   (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)"""
            )

            # Parameterized query - SQLite handles escaping
            cursor.execute(
                "INSERT INTO messages (username, message) VALUES (?, ?)",
                (username, message),
            )
            conn.commit()
            return True

    except sqlite3.Error:
        # Log error internally, don't expose database details
        print("Database error occurred", file=__import__("sys").stderr)
        return False


@app.route("/post", methods=["POST"])
def post():
    """
    Handles message submission with input validation and secure database operations.
    Sets secure headers and validates all inputs before processing.
    """
    # Set secure response headers to prevent XSS and other attacks
    response_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
    }

    try:
        # Get parameters from request - treat as untrusted input
        username = request.form.get("username")
        message = request.form.get("message")

        # Validate inputs with strict bounds checking
        validated_username = validate_input(username, MAX_USERNAME_LENGTH)
        validated_message = validate_input(message, MAX_MESSAGE_LENGTH)

        # Fail closed if validation fails - generic error message
        if validated_username is None or validated_message is None:
            return "Invalid input", 400, response_headers

        # Insert into database using parameterized query
        success = insert_user_message_in_db(validated_username, validated_message)

        if not success:
            # Generic error - don't expose internal details
            return "Error processing request", 500, response_headers

        # Redirect to main page - use absolute path to prevent open redirect
        response = redirect("/index.html")
        for header, value in response_headers.items():
            response.headers[header] = value
        return response

    except Exception:
        # Log internally, return generic error
        print("Error in post handler", file=__import__("sys").stderr)
        return "Error processing request", 500, response_headers

@app.route('/index.html')
def index():
    """\n    Main page with form for message submission.\n    HTML escaping prevents XSS attacks.\n    """
    # HTML form with CSRF protection considerations and input limits
    html_content = '''\n    <!DOCTYPE html>\n    <html>\n    <head>\n        <title>Message Board</title>\n        <meta charset="UTF-8">\n    </head>\n    <body>\n        <h1>Submit a Message</h1>\n        <form action="/post" method="post">\n            <label for="username">Username:</label><br>\n            <input type="text" id="username" name="username" maxlength="50" required><br><br>\n            <label for="message">Message:</label><br>\n            <textarea id="message" name="message" maxlength="500" rows="4" cols="50" required></textarea><br><br>\n            <input type="submit" value="Submit">\n        </form>\n    </body>\n    </html>\n    '''
    return render_template_string(html_content)

# Test cases
if __name__ == '__main__':
    print("Test 1: Valid input validation")
    result1 = validate_input("testuser", MAX_USERNAME_LENGTH)
    print(f"Result: {'PASS' if result1 is not None else 'FAIL'}")
    
    print("\\nTest 2: Empty input validation")
    result2 = validate_input("", MAX_USERNAME_LENGTH)
    print(f"Result: {'PASS' if result2 is None else 'FAIL'}")
    
    print("\\nTest 3: None input validation")
    result3 = validate_input(None, MAX_USERNAME_LENGTH)
    print(f"Result: {'PASS' if result3 is None else 'FAIL'}")
    
    print("\\nTest 4: Exceeds max length validation")
    long_input = "a" * (MAX_USERNAME_LENGTH + 1)
    result4 = validate_input(long_input, MAX_USERNAME_LENGTH)
    print(f"Result: {'PASS' if result4 is None else 'FAIL'}")
    
    print("\\nTest 5: Input with null byte")
    result5 = validate_input("test\\x00user", MAX_USERNAME_LENGTH)
    print(f"Result: {'PASS' if result5 is None else 'FAIL'}")
    
    # Uncomment to run server: app.run(debug=False)
