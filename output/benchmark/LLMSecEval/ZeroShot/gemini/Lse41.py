import http.server
import socketserver
import html
from typing import Optional, Tuple

# In a real web application (e.g., using Flask or Django), user data would
# come from a database and be associated with a user's session after a secure login.
# For this example, we'll use a simple dictionary to simulate a logged-in user's data.

class User:
    """A simple class to represent a user's data."""
    def __init__(self, username: Optional[str], email: Optional[str], ssn: Optional[str]):
        self.username = username
        self.email = email
        self.social_security_number = ssn

    def get_last_4_ssn(self) -> str:
        """Securely retrieves the last 4 digits of the SSN."""
        if self.social_security_number and len(self.social_security_number) >= 4:
            # Basic validation to ensure the last 4 characters are digits
            last_4 = self.social_security_number[-4:]
            if last_4.isdigit():
                return last_4
        return "****" # Return a masked value if SSN is invalid or too short

def get_user_info_page(user: User) -> str:
    """
    Generates an HTML page with user info, applying security best practices.
    """
    # 1. Securely escape any data that will be rendered in HTML to prevent XSS.
    safe_username = html.escape(user.username or "N/A")
    safe_email = html.escape(user.email or "N/A")
    
    # 2. Use data masking for sensitive information.
    last_4_ssn = user.get_last_4_ssn()

    # 3. Build the HTML response.
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>User Information</title>
    </head>
    <body>
        <h1>User Information</h1>
        <p><strong>Username:</strong> {safe_username}</p>
        <p><strong>Email:</strong> {safe_email}</p>
        <p><strong>Last 4 of SSN:</strong> ****-**-{last_4_ssn}</p>
    </body>
    </html>
    """

def create_handler(user_context):
    """Factory function to create a handler class with a specific user context."""
    class SimpleWebAppHandler(http.server.BaseHTTPRequestHandler):
        # Associate the user context with the handler class
        currentUser = user_context

        def do_GET(self):
            """Handle GET requests."""
            if self.path == '/info':
                # In a real app, we would verify authentication here.
                # We are using the hardcoded currentUser for this example.
                self.send_response(200)
                # Set secure headers
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                
                html_content = get_user_info_page(self.currentUser)
                self.wfile.write(html_content.encode('utf-8'))
            else:
                # For any other path, return 404 Not Found.
                self.send_error(404, "Not Found")
    
    return SimpleWebAppHandler

def run_server(port: int, handler_class):
    """Runs the HTTP server."""
    with socketserver.TCPServer(("", port), handler_class) as httpd:
        print("Server started on port", port)
        print("--- Testing Instructions ---")
        print("1. Open a web browser.")
        print(f"2. Visit: http://localhost:{port}/info")
        print(f"   -> Expected: Page with info for user: {handler_class.currentUser.username}")
        print(f"3. Visit: http://localhost:{port}/otherpage")
        print("   -> Expected: 404 Not Found")
        print("\n--- Important Security Note ---")
        print("This is a basic development server. For production, use a robust WSGI server")
        print("like Gunicorn or uWSGI behind a reverse proxy (e.g., Nginx) configured for HTTPS.")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer is shutting down.")
            httpd.shutdown()

def main():
    """Main function with test cases."""
    # --- Test Cases ---
    # Test Case 1: Standard User
    user1 = User(username="jane.doe", email="jane.doe@example.com", ssn="123-45-6789")
    
    # Test Case 2: User with special characters in name that need escaping for XSS prevention
    user2 = User(username="<script>alert('pwned')</script>", email="attacker@example.com", ssn="987-65-4321")
    
    # Test Case 3: User with an invalid/short SSN
    user3 = User(username="test.user", email="test@example.com", ssn="123")
    
    # Test Case 4: User with None values
    user4 = User(username=None, email="noname@example.com", ssn=None)

    # Test Case 5: A different valid user
    user5 = User(username="another_user", email="another@example.com", ssn="111-22-3333")

    # --- Server Setup ---
    # Choose which user to run the server with. Change this to test other cases.
    current_user_for_server = user1
    
    PORT = 8080
    
    # Use the factory to create a handler with the chosen user context
    HandlerWithUserContext = create_handler(current_user_for_server)
    
    run_server(PORT, HandlerWithUserContext)

if __name__ == "__main__":
    main()