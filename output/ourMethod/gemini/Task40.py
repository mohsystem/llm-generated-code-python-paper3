import http.server
import socketserver
import urllib.parse
from http.cookies import SimpleCookie
import secrets
import html
import os

# In-memory session store: {session_id: csrf_token}
SESSIONS = {}

class CsrfProtectedHandler(http.server.BaseHTTPRequestHandler):
    """
    A simple HTTP request handler that demonstrates CSRF protection.
    """

    def _get_session_id(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            if 'session_id' in cookie:
                return cookie['session_id'].value
        return None

    def _create_session(self):
        session_id = secrets.token_hex(16)
        csrf_token = secrets.token_hex(32)
        SESSIONS[session_id] = csrf_token
        return session_id, csrf_token

    def _send_response(self, status_code, content, headers=None):
        self.send_response(status_code)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def do_GET(self):
        if self.path == '/settings':
            session_id = self._get_session_id()
            headers = {}

            if session_id and session_id in SESSIONS:
                csrf_token = SESSIONS[session_id]
            else:
                session_id, csrf_token = self._create_session()
                cookie = SimpleCookie()
                cookie['session_id'] = session_id
                cookie['session_id']['httponly'] = True
                cookie['session_id']['path'] = '/'
                headers['Set-Cookie'] = cookie.output(header='').strip()

            html_form = f"""
            <html>
            <head><title>User Settings</title></head>
            <body>
                <h2>Update Settings</h2>
                <form action="/settings" method="post">
                    <label for="username">Username:</label><br>
                    <input type="text" id="username" name="username" value="testuser"><br><br>
                    <label for="email">Email:</label><br>
                    <input type="email" id="email" name="email" value="user@example.com"><br><br>
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <input type="submit" value="Update Settings">
                </form>
            </body>
            </html>
            """
            self._send_response(200, html_form, headers)
        else:
            self._send_response(404, "<html><body><h1>404 Not Found</h1></body></html>")

    def do_POST(self):
        if self.path == '/settings':
            session_id = self._get_session_id()
            if not session_id or session_id not in SESSIONS:
                self._send_response(403, "<html><body><h1>403 Forbidden: Invalid session</h1></body></html>")
                return

            expected_token = SESSIONS[session_id]

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)

            submitted_token = params.get('csrf_token', [None])[0]

            if not submitted_token or not secrets.compare_digest(expected_token, submitted_token):
                self._send_response(403, "<html><body><h1>403 Forbidden: Invalid CSRF token</h1></body></html>")
                return
            
            # CSRF check passed. Regenerate token for future requests.
            SESSIONS[session_id] = secrets.token_hex(32)

            username = html.escape(params.get('username', [''])[0])
            email = html.escape(params.get('email', [''])[0])
            
            print(f"Settings updated for session {session_id}: Username={username}, Email={email}")
            
            success_page = f"""
            <html><body>
                <h2>Settings Updated Successfully</h2>
                <p>Username: {username}</p>
                <p>Email: {email}</p>
                <a href="/settings">Go back</a>
            </body></html>
            """
            self._send_response(200, success_page)
        else:
            self._send_response(404, "<html><body><h1>404 Not Found</h1></body></html>")


def main():
    port = 8000
    with socketserver.TCPServer(("", port), CsrfProtectedHandler) as httpd:
        print("Server started on port", port)
        print("--- How to Test ---")
        print("1. Open a web browser and navigate to http://localhost:8000/settings")
        print("\n--- Test Cases ---")
        print("1. [SUCCESS] Normal submission: Fill out the form and click 'Update Settings'. You should see a success message.")
        print("2. [FAIL] Tampered CSRF Token: Use browser dev tools to change the value of the hidden 'csrf_token' input, then submit. You should get a 403 Forbidden error.")
        print("3. [FAIL] Missing CSRF Token: Use browser dev tools to delete the hidden 'csrf_token' input, then submit. You should get a 403 Forbidden error.")
        print("4. [FAIL] Stale CSRF Token: Open the form in two tabs. Submit the first one successfully. Then try to submit the second one. It should fail because the session CSRF token was regenerated after the first successful submission.")
        print("5. [FAIL] Cross-Site Request Forgery Simulation (using curl):")
        print("   Run this command in your terminal: \n   curl -X POST -d \"username=attacker&email=attacker@site.com&csrf_token=fake_token\" http://localhost:8000/settings -v --cookie \"session_id=...your_session_id_from_browser...\"")
        print("   (Replace ...your_session_id_from_browser... with the actual value from your browser's cookies). This should fail with a 403 error.")
        httpd.serve_forever()

if __name__ == "__main__":
    main()