
import html
import sys
from io import BytesIO

def html_escape(input_str):
    if input_str is None:
        return ""
    return html.escape(input_str, quote=True)

def http_hello_page(request_body, response):
    try:
        # Read username from request body with size limit
        max_size = 8192  # 8KB limit
        username = request_body.read(max_size).decode('utf-8', errors='ignore').strip()
        
        # Validate and sanitize username
        if len(username) > 100:
            username = username[:100]
        username = html_escape(username)
        
        # Construct HTML response
        outputbuf = []
        outputbuf.append("HTTP/1.1 200 OK\\r\\n")
        outputbuf.append("Content-Type: text/html; charset=UTF-8\\r\\n")
        outputbuf.append("X-Content-Type-Options: nosniff\\r\\n")
        outputbuf.append("X-Frame-Options: DENY\\r\\n")
        outputbuf.append("\\r\\n")
        outputbuf.append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\">")
        outputbuf.append("<title>Hello Page</title></head><body>")
        outputbuf.append(f"<h1>Hello, {username}!</h1>")
        outputbuf.append("</body></html>")
        
        # Write response
        response_text = ''.join(outputbuf)
        response.write(response_text.encode('utf-8'))
        response.flush()
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    finally:
        response.close()

def main():
    # Test cases
    test_usernames = [
        "Alice",
        "Bob<script>alert('xss')</script>",
        "Charlie&Sons",
        "Diana\"O'Neil\"",
        ""
    ]
    
    for test_user in test_usernames:
        print(f"Testing with username: {test_user}")
        input_stream = BytesIO(test_user.encode('utf-8'))
        output_stream = BytesIO()
        http_hello_page(input_stream, output_stream)
        print(output_stream.getvalue().decode('utf-8'))
        print("---")

if __name__ == "__main__":
    main()
