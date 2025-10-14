import http.server
import socketserver
import urllib.parse
import html

PORT = 8000

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            html_content = """
            <html>
            <head><title>User Input Form</title></head>
            <body>
                <h2>Enter your name:</h2>
                <form method="post" action="/">
                    <input type="text" name="username" autofocus>
                    <input type="submit" value="Submit">
                </form>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode("utf-8"))
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            # Parse form data
            params = urllib.parse.parse_qs(post_data.decode('utf-8'))
            username = params.get("username", [""])[0]

            # Security: Escape HTML to prevent Cross-Site Scripting (XSS)
            sanitized_username = html.escape(username)

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            response_html = f"""
            <html>
            <head><title>User Input Display</title></head>
            <body>
                <h2>Hello, {sanitized_username}!</h2>
                <a href="/">Go back</a>
            </body>
            </html>
            """
            self.wfile.write(response_html.encode("utf-8"))
        else:
            self.send_error(404, "File Not Found: {}".format(self.path))

def run_server():
    """
    Main function to set up and run the web server.
    """
    with socketserver.TCPServer(("", PORT), MyHttpRequestHandler) as httpd:
        print("Server started on port", PORT)
        print(f"Open http://localhost:{PORT} in your browser.")
        print("\n--- Manual Test Cases ---")
        print("1. Enter a simple name like 'Alice' and submit.")
        print("2. Enter a name with spaces like 'Bob Smith' and submit.")
        print("3. Enter text with special characters like '1 < 5 & 4 > 3' and submit.")
        print("4. Enter an XSS payload like '<script>alert(\"xss\")</script>' and verify it is displayed as text, not executed.")
        print("5. Submit the form with an empty input field.")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()