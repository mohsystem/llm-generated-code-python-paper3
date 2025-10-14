import http.server
import socketserver
import json
import sqlite3
import hashlib
import os
import sys
from http import HTTPStatus

# --- Configuration ---
PORT = 8080
DB_FILE = "users.db"

def setup_database():
    """Create the users table in the database if it doesn't exist."""
    # NOTE: In a production environment, use a more robust database
    # and manage credentials securely, not in a local file.
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
            """)
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        sys.exit(1)

def hash_password(password, salt):
    """Hashes a password with a given salt using PBKDF2-HMAC-SHA256."""
    # Rule #5: Use PBKDF2 with a high iteration count.
    # Rule #7: A unique salt is used for each password.
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        600000 # NIST recommended iteration count
    )
    return pwd_hash.hex()

class SimpleAPIHandler(http.server.BaseHTTPRequestHandler):
    """
    A simple HTTP request handler for the user creation API.
    """

    def _send_response(self, status_code, message_dict):
        """Helper to send a JSON response."""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(message_dict).encode('utf-8'))

    def do_POST(self):
        """Handles POST requests to create a new user."""
        if self.path == '/api/users':
            try:
                content_length = int(self.headers['Content-Length'])
                if content_length == 0:
                    self._send_response(HTTPStatus.BAD_REQUEST, {"error": "Request body is empty"})
                    return
                
                post_data = self.rfile.read(content_length)
                user_data = json.loads(post_data)

                # Rule #12: Validate input
                username = user_data.get('username')
                email = user_data.get('email')
                password = user_data.get('password')

                if not all([username, email, password]):
                    self._send_response(HTTPStatus.BAD_REQUEST, {"error": "Missing fields: username, email, and password are required"})
                    return
                
                if not isinstance(username, str) or not isinstance(email, str) or not isinstance(password, str) \
                   or not username.strip() or not email.strip() or not password:
                    self._send_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid data types or empty values"})
                    return

                # Rule #8: Use a cryptographically secure RNG for salts.
                salt = os.urandom(16)
                password_hash = hash_password(password, salt)

                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    # Use parameterized queries to prevent SQL injection
                    cursor.execute(
                        "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                        (username, email, password_hash, salt.hex())
                    )
                    user_id = cursor.lastrowid
                    conn.commit()
                    self._send_response(HTTPStatus.CREATED, {"message": "User created successfully", "id": user_id})

            except json.JSONDecodeError:
                self._send_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON format"})
            except sqlite3.IntegrityError:
                self._send_response(HTTPStatus.CONFLICT, {"error": "Username already exists"})
            except Exception as e:
                print(f"Internal server error: {e}", file=sys.stderr)
                self._send_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "An internal error occurred"})
        else:
            self._send_response(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_GET(self):
        self._send_response(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Method not allowed"})

def run_server():
    """Sets up and runs the HTTP server."""
    # NOTE: In a production environment, use a proper WSGI server (like Gunicorn or uWSGI)
    # and run it behind a reverse proxy (like Nginx). Also, enable HTTPS.
    with socketserver.TCPServer(("", PORT), SimpleAPIHandler) as httpd:
        print(f"Server started on port {PORT}")
        print("Use Ctrl+C to stop the server.")
        httpd.serve_forever()

def print_test_cases():
    base_url = f"http://localhost:{PORT}/api/users"
    print("\n--- API Test Cases ---")
    print("Run these curl commands in a separate terminal.\n")

    # Test Case 1: Successful user creation
    print("1. Create a new user (Success):")
    print(f"curl -X POST -H \"Content-Type: application/json\" -d '{{\"username\":\"pyuser1\",\"email\":\"py1@example.com\",\"password\":\"SecurePass1!\"}}' {base_url}")
    print()

    # Test Case 2: Attempt to create a user with a duplicate username
    print("2. Create a duplicate user (Conflict):")
    print(f"curl -X POST -H \"Content-Type: application/json\" -d '{{\"username\":\"pyuser1\",\"email\":\"another@example.com\",\"password\":\"AnotherPass1!\"}}' {base_url}")
    print()

    # Test Case 3: Request with a missing field
    print("3. Request with missing 'password' field (Bad Request):")
    print(f"curl -X POST -H \"Content-Type: application/json\" -d '{{\"username\":\"pyuser2\",\"email\":\"py2@example.com\"}}' {base_url}")
    print()

    # Test Case 4: Request with malformed JSON
    print("4. Request with malformed JSON (Bad Request):")
    print(f"curl -X POST -H \"Content-Type: application/json\" -d '{{\"username\":\"pyuser3\", \"email\":\"py3@example.com\",' {base_url}")
    print()

    # Test Case 5: Request to a wrong endpoint
    print("5. Request to a non-existent endpoint (Not Found):")
    print(f"curl -X POST -H \"Content-Type: application/json\" -d '{{\"data\":\"some data\"}}' http://localhost:{PORT}/api/nonexistent")
    print()

if __name__ == "__main__":
    setup_database()
    print_test_cases()
    run_server()