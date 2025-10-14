
from http.server import HTTPServer, BaseHTTPRequestHandler
import sqlite3
import re
import json
from typing import Optional
from urllib.parse import parse_qs, unquote
import secrets

NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\s]{1,100}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$')
MAX_INPUT_LENGTH = 1000
DB_FILE = 'users.db'


def init_database() -> None:
    conn = sqlite3.connect(DB_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                name TEXT NOT NULL,\n                email TEXT NOT NULL UNIQUE,\n                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        conn.commit()
    finally:
        conn.close()


def validate_input(input_str: Optional[str], pattern: re.Pattern, field_name: str) -> str:
    if not input_str:
        raise ValueError(f"{field_name} is required")
    if len(input_str) > MAX_INPUT_LENGTH:
        raise ValueError(f"{field_name} exceeds maximum length")
    trimmed = input_str.strip()
    if not pattern.match(trimmed):
        raise ValueError(f"{field_name} contains invalid characters")
    return trimmed


def store_user(name: str, email: str) -> dict:
    valid_name = validate_input(name, NAME_PATTERN, "Name")
    valid_email = validate_input(email, EMAIL_PATTERN, "Email")
    
    conn = sqlite3.connect(DB_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", (valid_name, valid_email))
        conn.commit()
        return {"status": "success", "message": "User created"}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "Email already exists"}
    finally:
        conn.close()


class UserHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != '/api/user':
            self.send_response(404)
            self.end_headers()
            return
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_INPUT_LENGTH:
                self.send_json_response(413, {"error": "Request too large"})
                return
            
            body = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(body)
            
            name = params.get('name', [None])[0]
            email = params.get('email', [None])[0]
            
            if name:
                name = unquote(name)
            if email:
                email = unquote(email)
            
            result = store_user(name, email)
            self.send_json_response(200, result)
            
        except ValueError as e:
            self.send_json_response(400, {"error": str(e)})
        except Exception:
            self.send_json_response(500, {"error": "Internal server error"})
    
    def send_json_response(self, status_code: int, data: dict) -> None:
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def log_message(self, format: str, *args) -> None:
        pass


def test_api_endpoint(name: str, email: str) -> None:
    import urllib.request
    from urllib.parse import urlencode
    
    try:
        data = urlencode({'name': name, 'email': email}).encode('utf-8')
        req = urllib.request.Request('http://localhost:8080/api/user', data=data, method='POST')
        with urllib.request.urlopen(req) as response:
            print(f"Test: {name} - Response: {response.status}")
    except Exception as e:
        print(f"Test failed: {str(e)}")


def display_users() -> None:
    print("\\nStored users:")
    conn = sqlite3.connect(DB_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name, email FROM users")
        for row in cursor.fetchall():
            print(f"Name: {row[0]}, Email: {row[1]}")
    finally:
        conn.close()


def main() -> None:
    init_database()
    
    server = HTTPServer(('localhost', 8080), UserHandler)
    print("Server started on port 8080")
    
    import threading
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    import time
    time.sleep(1)
    
    test_api_endpoint("John Doe", "john@example.com")
    test_api_endpoint("Jane Smith", "jane@example.com")
    test_api_endpoint("Bob_123", "bob@test.org")
    test_api_endpoint("Alice", "alice@domain.co.uk")
    test_api_endpoint("Charlie99", "charlie@mail.com")
    
    time.sleep(1)
    server.shutdown()
    display_users()


if __name__ == "__main__":
    main()
