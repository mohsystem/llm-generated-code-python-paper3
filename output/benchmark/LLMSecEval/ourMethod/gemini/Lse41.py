import os
import html
from http.server import BaseHTTPRequestHandler, HTTPServer

# In a production environment, this application should be run behind a production-grade
# web server (like Gunicorn) and a reverse proxy (like Nginx or Apache) that handles
# TLS (HTTPS) termination. Do not expose this development server directly to the internet.

class InfoRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the /info endpoint.
    """

    def do_GET(self):
        """Handles GET requests."""
        if self.path == "/info":
            self.handle_info_request()
        else:
            self.send_error(404, "Not Found")

    def handle_info_request(self):
        """
        Retrieves user info from environment variables and serves the HTML page.
        """
        # Rule #2: Avoid hardcoding credentials. Use environment variables.
        username = os.environ.get("USER_INFO_USERNAME")
        email = os.environ.get("USER_INFO_EMAIL")
        ssn = os.environ.get("USER_INFO_SSN")

        if not all([username, email, ssn]):
            print("Error: Required environment variables (USER_INFO_USERNAME, USER_INFO_EMAIL, USER_INFO_SSN) are not set.")
            self.send_error(500, "Internal Server Error: Server is not configured correctly.")
            return

        if len(ssn) < 4:
            print("Error: USER_INFO_SSN environment variable is too short.")
            self.send_error(500, "Internal Server Error: Invalid configuration.")
            return

        last_4_ssn = ssn[-4:]
        
        # Sanitize data before embedding in HTML to prevent XSS
        safe_username = html.escape(username)
        safe_email = html.escape(email)

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><title>User Information</title></head>
        <body>
        <h1>User Details</h1>
        <p><strong>Username:</strong> {safe_username}</p>
        <p><strong>Email:</strong> {safe_email}</p>
        <p><strong>SSN (Last 4 digits):</strong> XXX-XX-{last_4_ssn}</p>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

def run_server(server_class=HTTPServer, handler_class=InfoRequestHandler, port=8080):
    """Starts the HTTP server."""
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Server started on port {port}")
    print(f"Access the info page at http://localhost:{port}/info")
    print("Make sure to set the required environment variables before running.")
    print("Example (Linux/macOS):")
    print("export USER_INFO_USERNAME=\"testuser\"")
    print("export USER_INFO_EMAIL=\"test@example.com\"")
    print("export USER_INFO_SSN=\"123456789\"")
    print("python your_script_name.py")
    print("\n--- Test Cases ---")
    print("1. All env vars set correctly: Access /info, should see user data.")
    print("2. One or more env vars missing: Access /info, should see a 500 error.")
    print("3. SSN is less than 4 digits: Access /info, should see a 500 error.")
    print("4. Access a different path (e.g., /): Should see a 404 error.")
    print("5. Use a different method (e.g., POST): Standard library server sends 501/405 depending on implementation.")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()