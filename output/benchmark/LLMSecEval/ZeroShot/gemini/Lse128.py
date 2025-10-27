import html
import io

def http_hello_page(request, response):
    """
    Reads a username from a request stream, constructs a secure "hello [username]"
    HTML response, and writes it to the response stream.

    :param request: A file-like object for the request stream.
    :param response: A file-like object for the response stream.
    """
    # In a real application, you would parse a full HTTP request.
    # For this example, we assume the request stream contains only the username on a single line.
    username = request.readline().strip()

    # Securely escape the user-provided username to prevent XSS attacks
    # using the standard library's html.escape function.
    escaped_username = html.escape(username)
    
    http_response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n\r\n"
        f"<html><body>hello {escaped_username}</body></html>"
    )
    
    response.write(http_response)
    response.flush()

if __name__ == '__main__':
    test_inputs = [
        "Alice",                                  # Test case 1: Normal input
        "Bob Smith",                              # Test case 2: Input with spaces
        "",                                       # Test case 3: Empty input
        "<script>alert('XSS')</script>",          # Test case 4: XSS attack attempt
        "John&Doe\" onload=\"alert('hacked')\""   # Test case 5: XSS attack with quotes and ampersand
    ]
    
    for i, test_input in enumerate(test_inputs):
        print(f"--- Test Case {i + 1} ---")
        print(f"Input: {test_input}")

        # Simulate file streams using io.StringIO
        request_stream = io.StringIO(test_input)
        response_stream = io.StringIO()
        
        http_hello_page(request_stream, response_stream)
        
        print("Output:")
        print(response_stream.getvalue())
        print()