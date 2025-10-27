
import sqlite3
import re
import os
from urllib.parse import parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import html

# Database configuration from environment variables
DB_PATH = os.environ.get('DB_PATH', 'subscribers.db')

# Email validation pattern - RFC 5322 simplified
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$')

# Maximum email length to prevent DOS
MAX_EMAIL_LENGTH = 254

def is_valid_email(email):
    """\n    Validates email format and length\n    Args:\n        email: Email string to validate\n    Returns:\n        bool: True if valid, False otherwise\n    """
    if not email or not isinstance(email, str):
        return False
    if len(email) > MAX_EMAIL_LENGTH:
        return False
    return EMAIL_PATTERN.match(email) is not None
def initialize_database():
    """
    Initializes database with subscribers table
    """
    try:
        # Use context manager for automatic connection closing
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS subscribers (
                                                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                           email TEXT UNIQUE NOT NULL
                )
                """
            )
            conn.commit()
    except sqlite3.Error:
        # Log error internally but don't expose details
        print("Database initialization failed", file=__import__("sys").stderr)


def handle_unsubscribe(email):
    """
    Handles unsubscribe request
    Args:
        email: Email address to unsubscribe
    Returns:
        str: Response message
    """
    # Input validation - check for None/empty
    if email is None or not email.strip():
        return "Invalid request: email parameter is required"

    # Trim and normalize input
    email = email.strip().lower()

    # Validate email format and length
    if not is_valid_email(email):
        return "Invalid email format"

    try:
        # Use context manager for automatic resource cleanup
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            # First check if email exists - using parameterized query to prevent SQL injection
            cursor.execute("SELECT COUNT(*) FROM subscribers WHERE email = ?", (email,))
            count = cursor.fetchone()[0]

            if count > 0:
                # Email exists, proceed with deletion using parameterized query
                cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
                conn.commit()

                if cursor.rowcount > 0:
                    return "Successfully unsubscribed"
                else:
                    # Unexpected case - log internally
                    return "Unsubscribe failed"
            else:
                # Email not found in database
                return "Email address is not subscribed"

    except sqlite3.Error:
        # Log error details internally, return generic message
        print("Database error occurred", file=__import__("sys").stderr)
        return "An error occurred processing your request"


class UnsubscribeHandler(BaseHTTPRequestHandler):
    """
    HTTP handler for unsubscribe endpoint
    """

    def do_GET(self):
        """Handle GET requests"""
        try:
            # Parse URL and query parameters
            parsed_url = urlparse(self.path)

            # Only handle /unsubscribe endpoint
            if parsed_url.path != "/unsubscribe":
                self.send_error(404, "Not Found")
                return

            # Parse query parameters safely
            query_params = parse_qs(parsed_url.query)
            email = query_params.get("email", [None])[0]

            # Handle unsubscribe
            response = handle_unsubscribe(email)

            # Send response
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(response.encode("utf-8"))

        except Exception:
            # Catch any unexpected exceptions
            self.send_error(500, "Internal Server Error")

    def log_message(self, format, *args):
        """Override to control logging"""
        pass

def main():
    """Main function with test cases"""
    # Initialize database
    initialize_database()
    
    # Test cases
    print("Test Case 1 - Valid email unsubscribe:")
    print(handle_unsubscribe("test@example.com"))
    
    print("\\nTest Case 2 - Email not in database:")
    print(handle_unsubscribe("notfound@example.com"))
    
    print("\\nTest Case 3 - Invalid email format:")
    print(handle_unsubscribe("invalid-email"))
    
    print("\\nTest Case 4 - None email:")
    print(handle_unsubscribe(None))
    
    print("\\nTest Case 5 - Empty email:")
    print(handle_unsubscribe(""))

if __name__ == "__main__":
    main()
