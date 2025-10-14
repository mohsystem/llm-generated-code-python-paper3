import http.server
import socketserver
import uuid
import time
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie
import threading

# Global in-memory session store and a lock for thread safety
SESSION_STORE = {}
SESSION_LOCK = threading.Lock()
SESSION_TIMEOUT_SECONDS = 300  # 5 minutes

# Dummy user database
USERS = {"testuser": "password123"}

class SessionManager:
    @staticmethod
    def create_session(username):
        """Creates a new session and returns the session ID."""
        session_id = str(uuid.uuid4())
        expires = time.time() + SESSION_TIMEOUT_SECONDS
        with SESSION_LOCK:
            SESSION_STORE[session_id] = {"username": username, "expires": expires}
        return session_id

    @staticmethod
    def get_session(session_id):
        """Retrieves session data if the session is valid and not expired."""
        if not session_id:
            return None
        with SESSION_LOCK:
            session = SESSION_STORE.get(session_id)
            if session and time.time() < session["expires"]:
                return session
            elif session: # Session has expired
                del SESSION_STORE[session_id]
        return None

    @staticmethod
    def terminate_session(session_id):
        """Terminates a session by removing it from the store."""
        if not session_id:
            return
        with SESSION_LOCK:
            if session_id in SESSION_STORE:
                del SESSION_STORE[session_id]

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def _send_response(self, code, message, headers=None):
        self.send_response(code)
        if headers:
            for key, val in headers.items():
                self.send_header(key, val)
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)

        if path == "/login":
            self.handle_login(query)
        elif path == "/profile":
            self.handle_profile()
        elif path == "/logout":
            self.handle_logout()
        else:
            self._send_response(404, "Not Found")

    def handle_login(self, query):
        username = query.get('username', [None])[0]
        password = query.get('password', [None])[0]

        if username in USERS and USERS[username] == password:
            session_id = SessionManager.create_session(username)
            cookie = SimpleCookie()
            cookie["session_id"] = session_id
            cookie["session_id"]["httponly"] = True
            cookie["session_id"]["path"] = "/"
            
            headers = {'Content-type': 'text/plain'}
            for morsel in cookie.values():
                headers['Set-Cookie'] = morsel.output(header='').strip()
            
            self._send_response(200, "Login successful.", headers)
        else:
            self._send_response(401, "Invalid credentials.")

    def handle_profile(self):
        cookie_header = self.headers.get('Cookie')
        session_id = None
        if cookie_header:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            if "session_id" in cookie:
                session_id = cookie["session_id"].value

        session = SessionManager.get_session(session_id)
        if session:
            message = f"Hello, {session['username']}. Welcome to your profile."
            self._send_response(200, message)
        else:
            self._send_response(401, "Unauthorized. Please log in.")

    def handle_logout(self):
        cookie_header = self.headers.get('Cookie')
        session_id = None
        if cookie_header:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            if "session_id" in cookie:
                session_id = cookie["session_id"].value
        
        SessionManager.terminate_session(session_id)
        
        # Expire cookie on client side
        cookie = SimpleCookie()
        cookie["session_id"] = ""
        cookie["session_id"]["path"] = "/"
        cookie["session_id"]["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"

        headers = {'Content-type': 'text/plain'}
        for morsel in cookie.values():
            headers['Set-Cookie'] = morsel.output(header='').strip()

        self._send_response(200, "Logged out successfully.", headers)

def run_server(server_class=socketserver.TCPServer, handler_class=MyHttpRequestHandler, port=8081):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Server started on port {port}")
    print("--- Test Cases (run in your terminal) ---")
    print("1. Login (Success):")
    print("   curl \"http://localhost:8081/login?username=testuser&password=password123\" -c cookie.txt -v")
    print("\n2. Access Profile with Session Cookie (Success):")
    print("   curl http://localhost:8081/profile -b cookie.txt")
    print("\n3. Access Profile without Session Cookie (Failure):")
    print("   curl http://localhost:8081/profile")
    print("\n4. Logout:")
    print("   curl http://localhost:8081/logout -b cookie.txt")
    print("\n5. Access Profile after Logout (Failure):")
    print("   curl http://localhost:8081/profile -b cookie.txt")
    httpd.serve_forever()

if __name__ == "__main__":
    # Using ThreadingTCPServer to handle concurrent requests gracefully
    run_server(server_class=socketserver.ThreadingTCPServer)