
from http.server import HTTPServer, BaseHTTPRequestHandler
import psycopg2
import os
import re
from urllib.parse import urlparse, parse_qs
import ssl

# Database connection parameters from environment variables
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_NAME = os.environ.get('DB_NAME', 'testdb')
DB_USER = os.environ.get('DB_USER', 'testuser')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'testpass')

# Input validation: alphanumeric and underscore only, max 50 chars
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{1,50}$')


def check_moderator(username):
    """\n    Checks if a user is a moderator by querying the database.\n    Uses parameterized query to prevent SQL injection.\n    \n    Args:\n        username: The username to check (already validated)\n        \n    Returns:\n        bool: True if moderator, False if not, None on error\n    """
    # Validate input before database query
    if not username or not USERNAME_PATTERN.match(username):
        return False
    
    conn = None
    try:
        # Connect to database with connection timeout
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=5
        )
        
        # Use cursor with automatic cleanup
        with conn.cursor() as cursor:
            # Parameterized query prevents SQL injection
            sql = "SELECT is_moderator FROM users WHERE username = %s"
            cursor.execute(sql, (username,))
            
            result = cursor.fetchone()
            if result:
                return bool(result[0])
            return False  # User not found
            
    except psycopg2.Error:
        # Log error without exposing internal details
        print("Database query failed", flush=True)
        return None  # Indicate error condition
    finally:
        if conn:
            conn.close()


class ModeratorHandler(BaseHTTPRequestHandler):
    """HTTP request handler for moderator check endpoint"""
    
    def do_GET(self):
        """Handle GET requests to check moderator status"""
        try:
            # Parse URL and query parameters
            parsed_url = urlparse(self.path)
            
            if parsed_url.path != '/check-moderator':
                self.send_error(404, "Not found")
                return
            
            # Extract and validate username parameter
            query_params = parse_qs(parsed_url.query)
            if 'username' not in query_params:
                self.send_error(400, "Invalid request")
                return
            
            username = query_params['username'][0]
            
            # Validate username format
            if not USERNAME_PATTERN.match(username):
                self.send_error(400, "Invalid request")
                return
            
            # Check moderator status
            is_moderator = check_moderator(username)
            
            if is_moderator is None:
                self.send_error(503, "Service unavailable")
                return
            
            # Send success response
            response = "User is moderator" if is_moderator else "User is not moderator"
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
            
        except Exception:
            # Generic error response without internal details
            self.send_error(500, "Request processing failed")
    
    def log_message(self, format, *args):
        """Override to prevent logging sensitive information"""
        pass


def run_tests():
    """Run test cases for check_moderator function"""
    test_cases = ["admin", "user123", "moderator1", "guest", "invalid-user!"]
    
    for username in test_cases:
        print(f"Testing username: {username}")
        result = check_moderator(username)
        if result is None:
            print("Result: Database error")
        else:
            print(f"Result: {'Moderator' if result else 'Not moderator'}")


if __name__ == '__main__':
    # Run test cases
    run_tests()
    
    # Start web server
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, ModeratorHandler)
    print("Server started on port 8080")
    httpd.serve_forever()
