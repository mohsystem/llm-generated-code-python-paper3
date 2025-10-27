import http.server
import socketserver
import urllib.parse
import re
import html

# --- Constants ---
PORT = 8000
MAX_USERNAME_LENGTH = 32
MAX_MESSAGE_LENGTH = 256
# Simple alphanumeric pattern for username validation
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]+$")

# --- Mock Database Function ---
def insert_user_message_in_db(username, message):
    """Mocks inserting a user message into a database."""
    print(f"DATABASE: Inserting message for user '{username}': '{message}'")
    # In a real application, this would interact with a database.
    # Returning True to simulate success.
    return True

# --- Core Logic for Testing ---
def handle_post_logic(username, message):
    """The core logic for handling a post, separated for testability."""
    if not username:
        return "Username cannot be empty."
    if not message:
        return "Message cannot be empty."
    if len(username) > MAX_USERNAME_LENGTH:
        return "Username is too long."
    if len(message) > MAX_MESSAGE_LENGTH:
        return "Message is too long."
    if not USERNAME_PATTERN.match(username):
        return "Username contains invalid characters."
    
    # In a real application, use a proper sanitization/escaping library
    # before DB insertion to prevent SQL injection.
    # For display, html.escape() prevents XSS if we were to show the message.
    safe_message_for_db = message 
    
    if insert_user_message_in_db(username, safe_message_for_db):
        return "Success"
    else:
        return "Failed to save message."

# --- HTTP Request Handler ---
class MyHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        """Handles GET requests to the root path, serving the form."""
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            form_html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Message Board</title></head>
            <body>
                <h1>Post a Message</h1>
                <form action="/post" method="post">
                    <label for="username">Username:</label><br>
                    <input type="text" id="username" name="username" required maxlength="{MAX_USERNAME_LENGTH}"><br><br>
                    <label for="message">Message:</label><br>
                    <textarea id="message" name="message" rows="4" cols="50" required maxlength="{MAX_MESSAGE_LENGTH}"></textarea><br><br>
                    <input type="submit" value="Submit">
                </form>
            </body>
            </html>
            """
            self.wfile.write(form_html.encode('utf-8'))
        else:
            self.send_error(404, 'File Not Found: %s' % self.path)

    def post(self):
        """Handles POST requests to /post."""
        content_length = int(self.headers['Content-Length'])
        if content_length > (MAX_USERNAME_LENGTH + MAX_MESSAGE_LENGTH + 50): # Generous buffer
             self.send_error(413, "Payload too large") # 413 Payload Too Large
             return

        post_data_bytes = self.rfile.read(content_length)
        post_data = urllib.parse.parse_qs(post_data_bytes.decode('utf-8'))

        username = post_data.get('username', [None])[0]
        message = post_data.get('message', [None])[0]

        result = handle_post_logic(username, message)
        
        if result == "Success":
            # Redirect user back to the main page
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
        else:
            # Handle error
            self.send_response(400)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            escaped_result = html.escape(result)
            error_html = f"<html><body><h1>Error: {escaped_result}</h1><a href=\"/\">Go back</a></body></html>"
            self.wfile.write(error_html.encode('utf-8'))

    def do_POST(self):
        """Delegates POST requests to the post() method."""
        if self.path == '/post':
            self.post()
        else:
            self.send_error(404, 'File Not Found: %s' % self.path)
            
# --- Test Cases ---
def run_tests():
    """Runs test cases against the core logic function."""
    print("--- Running Test Cases ---")
    # Test Case 1: Valid input
    print("Test 1:", handle_post_logic("testuser", "Hello World!"))
    # Test Case 2: Empty username
    print("Test 2:", handle_post_logic("", "A message from nowhere."))
    # Test Case 3: Empty message
    print("Test 3:", handle_post_logic("anotheruser", ""))
    # Test Case 4: Username too long
    long_username = 'a' * (MAX_USERNAME_LENGTH + 1)
    print("Test 4:", handle_post_logic(long_username, "Short message."))
    # Test Case 5: Message too long
    long_message = 'b' * (MAX_MESSAGE_LENGTH + 1)
    print("Test 5:", handle_post_logic("shortuser", long_message))
    print("--- Test Cases Finished ---\n")

# --- Main Execution ---
if __name__ == "__main__":
    run_tests()
    
    Handler = MyHttpRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving at port {PORT}")
        print(f"Open http://localhost:{PORT} in your browser.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
            httpd.shutdown()