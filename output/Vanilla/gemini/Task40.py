import http.server
import socketserver
import urllib.parse
import secrets
from http import cookies

# In-memory storage for session CSRF tokens and user data.
# In a real application, this would be a persistent store or a distributed cache.
SESSION_CSRF_TOKENS = {}
USER_SETTINGS = {}

PORT = 8081

class CSRFRequestHandler(http.server.BaseHTTPRequestHandler):

    def get_or_create_session_id(self):
        cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
        session_id = cookie.get('session_id').value if 'session_id' in cookie else None
        
        if not session_id or session_id not in SESSION_CSRF_TOKENS:
            session_id = secrets.token_hex(16)
            self.send_header('Set-Cookie', f'session_id={session_id}; HttpOnly; Path=/')
        
        return session_id

    def do_GET(self):
        if self.path == '/settings':
            session_id = self.get_or_create_session_id()
            
            # Generate a new CSRF token for the form page
            csrf_token = secrets.token_hex(16)
            SESSION_CSRF_TOKENS[session_id] = csrf_token

            current_username = USER_SETTINGS.get(session_id, "DefaultUser")
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html_content = f"""
            <html>
            <head><title>User Settings</title></head>
            <body>
            <h2>Update User Settings</h2>
            <form action='/update-settings' method='post'>
            <input type='hidden' name='csrf_token' value='{csrf_token}' />
            <label for='username'>Username:</label><br>
            <input type='text' id='username' name='username' value='{current_username}'><br><br>
            <input type='submit' value='Update Settings'>
            </form>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode('utf-8'))
        else:
            self.send_error(404, 'Not Found')

    def do_POST(self):
        if self.path == '/update-settings':
            cookie = cookies.SimpleCookie(self.headers.get('Cookie'))
            session_id = cookie.get('session_id').value if 'session_id' in cookie else None

            if not session_id or session_id not in SESSION_CSRF_TOKENS:
                self.send_error(403, 'CSRF Token Invalid (No active session)')
                return
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            
            submitted_token = params.get('csrf_token', [None])[0]
            expected_token = SESSION_CSRF_TOKENS.get(session_id)

            if not submitted_token or not secrets.compare_digest(submitted_token, expected_token):
                self.send_error(403, 'CSRF Token Invalid')
                return

            # CSRF token is valid. Invalidate it to prevent reuse and process the request.
            del SESSION_CSRF_TOKENS[session_id]

            new_username = params.get('username', [''])[0]
            if new_username.strip():
                USER_SETTINGS[session_id] = new_username

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            success_response = """
            <html><body>
            <h2>Settings updated successfully!</h2>
            <a href='/settings'>Go back to settings</a>
            </body></html>
            """
            self.wfile.write(success_response.encode('utf-8'))
        else:
            self.send_error(404, 'Not Found')

def main():
    with socketserver.TCPServer(("", PORT), CSRFRequestHandler) as httpd:
        print(f"Server started on port {PORT}")
        print("--- CSRF Protection Test Cases ---")
        print("Open your web browser and follow these steps:")
        print("\n1. Test Case 1 (Normal Load):")
        print(f"   - Go to http://localhost:{PORT}/settings")
        print("   - The user settings form should be displayed.")
        
        print("\n2. Test Case 2 (Valid Submission):")
        print("   - On the form, enter a new username (e.g., 'test_user').")
        print("   - Click 'Update Settings'.")
        print("   - You should see a 'Settings updated successfully!' message.")
        print(f"   - Go back to http://localhost:{PORT}/settings, the new username should be pre-filled.")
        
        print("\n3. Test Case 3 (Invalid CSRF Token):")
        print(f"   - Load the form at http://localhost:{PORT}/settings.")
        print("   - Use browser developer tools to change the value of the hidden 'csrf_token' input to 'invalid_token'.")
        print("   - Submit the form.")
        print("   - You should see a 'CSRF Token Invalid' error (403 Forbidden).")
        
        print("\n4. Test Case 4 (Missing CSRF Token):")
        print(f"   - Load the form at http://localhost:{PORT}/settings.")
        print("   - Use browser developer tools to delete the hidden 'csrf_token' input field entirely.")
        print("   - Submit the form.")
        print("   - You should see a 'CSRF Token Invalid' error (403 Forbidden).")

        print("\n5. Test Case 5 (Using Stale/Old Token):")
        print(f"   - Open http://localhost:{PORT}/settings in two separate browser tabs (Tab A and Tab B).")
        print("   - In Tab A, submit a valid change (e.g., username 'user_a').")
        print("   - Now, go to Tab B (do not refresh it). The form in Tab B still has the old CSRF token.")
        print("   - In Tab B, try to submit a change (e.g., username 'user_b').")
        print("   - The submission from Tab B should fail with a 'CSRF Token Invalid' error because the token was already used/invalidated by the submission from Tab A.")
        
        httpd.serve_forever()

if __name__ == "__main__":
    main()