import html
import io

MAX_USERNAME_LENGTH = 128

def http_hello_page(request_stream, response_stream):
    """
    Handles a request for /hello, reading a username and writing a greeting page.

    :param request_stream: A file-like object for the request body (binary).
    :param response_stream: A file-like object for the response (binary).
    """
    # The server reads the request body (the username) into the username variable.
    # Read up to a maximum length to prevent resource exhaustion.
    try:
        username_bytes = request_stream.read(MAX_USERNAME_LENGTH)
        username = username_bytes.decode('utf-8')
    except Exception:
        username = "Guest" # Fallback on error

    if not username:
        username = "Guest"

    # Sanitize the username to prevent XSS attacks.
    sanitized_username = html.escape(username)

    # The server constructs the response body (the HTML page).
    outputbuf = f"<html><body><h1>Hello, {sanitized_username}!</h1></body></html>"
    
    # The server writes the response body to the response stream.
    try:
        response_stream.write(outputbuf.encode('utf-8'))
    except Exception as e:
        # In a real server, this should be logged.
        print(f"Error writing to response stream: {e}")
    finally:
        # The prompt implies the function closes the stream. In many frameworks,
        # this is handled by the server or a context manager. Here, we assume
        # the caller will manage the stream's lifecycle.
        pass

if __name__ == '__main__':
    test_cases = [
        "Alice",
        "Bob<script>alert(1)</script>",
        "",  # Empty username
        "Charles & David",
        "Eve's \"special\" username that is quite long to test the boundaries and see how it behaves with more characters"
    ]

    for i, test_case in enumerate(test_cases, 1):
        print(f"--- Test Case {i} ---")
        print(f"Input Username: {test_case}")

        request_body = test_case.encode('utf-8')
        request_stream = io.BytesIO(request_body)
        response_stream = io.BytesIO()

        http_hello_page(request_stream, response_stream)
        
        # The server closes the response stream.
        response_stream.seek(0)
        output_html = response_stream.read().decode('utf-8')
        
        request_stream.close()
        response_stream.close()

        print(f"Output HTML: {output_html}")
        print()