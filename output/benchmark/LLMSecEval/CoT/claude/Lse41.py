
from http.server import HTTPServer, BaseHTTPRequestHandler
import html
import re

class Lse41:
    class User:
        def __init__(self, username, email, ssn_last4, token):
            self.username = html.escape(username) if username else ""
            self.email = html.escape(email) if email else ""
            # Only store last 4 digits, validate format
            if ssn_last4 and re.match(r'^\\d{4}$', ssn_last4):
                self.ssn_last4 = ssn_last4
            else:
                self.ssn_last4 = "****"
            self.session_token = token
    
    @staticmethod
    def authenticate_user(token):
        # Simulated user database - in production, use secure database
        if token == "valid_token_123":
            return Lse41.User("john_doe", "john@example.com", "5678", token)
        return None
    
    class InfoHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/info':
                # Simple token-based auth (use proper OAuth/JWT in production)
                auth_header = self.headers.get('Authorization')
                user = Lse41.authenticate_user(auth_header)
                
                if user is None:
                    self.send_response(401)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('X-Frame-Options', 'DENY')
                    self.end_headers()
                    response = "<html><body><h1>Unauthorized</h1></body></html>"
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('X-Frame-Options', 'DENY')
                    self.end_headers()
                    response = f"""<html>\n                    <head><meta charset='UTF-8'></head>\n                    <body>\n                    <h1>User Information</h1>\n                    <p>Username: {user.username}</p>\n                    <p>Email: {user.email}</p>\n                    <p>SSN Last 4: ****-{user.ssn_last4}</p>\n                    </body>\n                    </html>"""
                
                self.wfile.write(response.encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()
        
        def log_message(self, format, *args):
            # Suppress default logging to avoid sensitive data exposure
            pass
    
    @staticmethod
    def main():
        print("Testing with 5 scenarios:")
        print("1. Valid token: curl -H 'Authorization: valid_token_123' http://localhost:8080/info")
        print("2. Invalid token: curl -H 'Authorization: invalid' http://localhost:8080/info")
        print("3. No token: curl http://localhost:8080/info")
        print("4. XSS attempt in username (blocked by html.escape)")
        print("5. Valid user data display with masked SSN")
        
        server = HTTPServer(('localhost', 8080), Lse41.InfoHandler)
        print("Server started on port 8080. Press Ctrl+C to stop.")
        server.serve_forever()

if __name__ == '__main__':
    Lse41.main()
