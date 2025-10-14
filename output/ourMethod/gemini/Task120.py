import html
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
from typing import Optional

def generate_web_page(user_input: Optional[str]) -> str:
    """
    Generates a full HTML page displaying user-supplied input.
    The input is sanitized using html.escape to prevent XSS.

    Args:
        user_input: The string provided by the user.

    Returns:
        A complete HTML page as a string.
    """
    if user_input is None:
        user_input = "No input provided."

    # Sanitize the input to prevent XSS attacks
    escaped_input = html.escape(user_input)
    
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>User Input Display</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>User-Supplied Input:</h1>
    <p style="border: 1px solid black; padding: 10px; background-color: #f0f0f0;">
        {escaped_input}
    </p>
</body>
</html>
"""

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        
        # Get the 'input' parameter, if it exists
        user_input_list = query_params.get('input', [None])
        user_input = user_input_list[0]

        html_content = generate_web_page(user_input)
        
        self.wfile.write(bytes(html_content, "utf8"))
        return

def main():
    """Main function to run test cases and optionally start the server."""
    # --- Test cases for the core logic ---
    print("--- Testing generate_web_page Function ---")
    
    # Test Case 1: Simple text
    input1 = "Hello, world!"
    print(f"Test Case 1 (Simple Text):\n{generate_web_page(input1)}\n")
    
    # Test Case 2: Text with HTML characters
    input2 = "<p>This is a paragraph.</p>"
    print(f"Test Case 2 (HTML Chars):\n{generate_web_page(input2)}\n")
    
    # Test Case 3: XSS attack attempt
    input3 = "<script>alert('XSS');</script>"
    print(f"Test Case 3 (XSS Attempt):\n{generate_web_page(input3)}\n")
    
    # Test Case 4: Text with quotes and ampersand
    input4 = "AT&T's new motto is \"Rethink Possible\"."
    print(f"Test Case 4 (Quotes & Ampersand):\n{generate_web_page(input4)}\n")
    
    # Test Case 5: None input
    input5 = None
    print(f"Test Case 5 (None Input):\n{generate_web_page(input5)}\n")

    # --- Optional: Start a web server to see it in a browser ---
    port = 8080
    try:
        handler_object = MyHttpRequestHandler
        my_server = socketserver.TCPServer(("", port), handler_object)
        print(f"--- Server started on port {port} ---")
        print("Try accessing: http://localhost:8080/?input=Your%20Text%20Here")
        print("Or for an XSS test: http://localhost:8080/?input=%3Cscript%3Ealert(1)%3C/script%3E")
        my_server.serve_forever()
    except OSError as e:
        print(f"Could not start server on port {port}: {e}. The port may be in use.")

if __name__ == "__main__":
    main()