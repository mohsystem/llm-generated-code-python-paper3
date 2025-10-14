import http.server
import socketserver
from urllib.parse import parse_qs
import html

PORT = 8080

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            form_html = """
            <!DOCTYPE html>
            <html>
            <head><title>User Input Form</title></head>
            <body>
            <h2>Enter some text:</h2>
            <form action="/submit" method="post">
            <input type="text" name="user_input" size="50">
            <br><br>
            <input type="submit" value="Submit">
            </form>
            </body>
            </html>
            """
            self.wfile.write(form_html.encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == '/submit':
            try:
                content_length = int(self.headers['Content-Length'])
                # Rule #3: Adhere to buffer boundaries. Reading only content_length.
                if content_length > 1024 * 10: # Limit input size to 10KB
                    self.send_error(413, "Payload Too Large")
                    return
                post_data = self.rfile.read(content_length)
                
                # Rule #1: Input validation and sanitization
                params = parse_qs(post_data.decode('utf-8'))
                user_input = params.get('user_input', [''])[0]
                
                # Rule #2: Sanitize output to prevent XSS
                sanitized_input = html.escape(user_input)
                
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                
                response_html = f"""
                <!DOCTYPE html>
                <html>
                <head><title>Submission Result</title></head>
                <body>
                <h2>You submitted:</h2>
                <p style="font-family: monospace; background-color: #f0f0f0; padding: 1em;">{sanitized_input}</p>
                <a href="/">Go back</a>
                </body>
                </html>
                """
                self.wfile.write(response_html.encode("utf-8"))
            except Exception as e:
                self.send_error(500, f"Server Error: {e}")
        else:
            self.send_error(404, "Not Found")

def main():
    """
    Main function to run the web server.
    Test cases for a web server are performed by a user through a browser.
    """
    with socketserver.TCPServer(("", PORT), SimpleHTTPRequestHandler) as httpd:
        print(f"Serving at port {PORT}")
        print(f"Open http://localhost:{PORT}/ in your browser.")
        print("The main function starts the server. Manual testing is required.")
        print("Test Case 1: Enter 'Hello World'.")
        print("Test Case 2: Enter '12345'.")
        print("Test Case 3: Enter an empty string.")
        print("Test Case 4: Enter 'Special Chars: &<>\"'.")
        print("Test Case 5: Enter '<script>alert(\"XSS Test\")</script>'.")
        httpd.serve_forever()

if __name__ == "__main__":
    main()