
import urllib.parse
import html
import io

def http_hello_page(request, response):
    username = None
    
    # Read headers
    line = request.readline()
    while line and line.strip():
        line = request.readline()
    
    # Read body
    body = request.read()
    
    # Parse username from body
    if 'username=' in body:
        parts = body.split('username=')
        if len(parts) > 1:
            username = parts[1].split('&')[0]
            # Decode URL encoding and sanitize
            username = urllib.parse.unquote(username)
            username = sanitize_input(username)
    
    if not username:
        username = "Guest"
    
    # Construct and write response
    response.write("HTTP/1.1 200 OK\\r\\n")
    response.write("Content-Type: text/html\\r\\n")
    response.write("\\r\\n")
    response.write("<html><body>\\r\\n")
    response.write(f"<h1>Hello {escape_html(username)}</h1>\\r\\n")
    response.write("</body></html>\\r\\n")
    response.flush()

def sanitize_input(input_str):
    if not input_str:
        return ""
    # Remove control characters and limit length
    sanitized = ''.join(char for char in input_str if not char.isspace() or char == ' ')
    return sanitized[:100]

def escape_html(input_str):
    if not input_str:
        return ""
    return html.escape(input_str)

if __name__ == "__main__":
    print("Test cases for http_hello_page:")
    
    test_cases = [
        "username=John",
        "username=Alice%20Smith",
        "username=%3Cscript%3Ealert%28%29%3C%2Fscript%3E",
        "username=",
        "username=Bob&other=data"
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\\nTest Case {i}:")
        try:
            request_str = f"POST / HTTP/1.1\\r\\n\\r\\n{test_case}"
            request = io.StringIO(request_str)
            response = io.StringIO()
            
            http_hello_page(request, response)
            print(response.getvalue())
        except Exception as e:
            print(f"Error: {e}")
