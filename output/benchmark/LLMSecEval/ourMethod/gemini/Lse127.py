import html
import io
import sys

MAX_USERNAME_LEN = 256

def http_hello_page(request, response):
    """
    Reads a username from the request stream and writes a hello message
    to the response stream.
    The function reads with a boundary to prevent DoS from very long lines,
    and sanitizes the username to prevent XSS.
    """
    # Read with a boundary to prevent DoS from a very long line.
    # We read one extra byte to detect if the line is too long.
    line = request.readline(MAX_USERNAME_LEN + 1)
    
    # Validate input length.
    if len(line) > MAX_USERNAME_LEN:
        # Input is too long, reject by treating as a generic user.
        username = "Guest"
    else:
        username = line.strip()

    if not username:
        username = "Guest"

    # Sanitize input for HTML context to prevent XSS.
    sanitized_username = html.escape(username)
    
    response.write(f"Hello {sanitized_username}")
    response.flush()

def main():
    """Main function with test cases."""
    test_cases = [
        ("Alice", "Hello Alice"),
        ("Bob\nnextline", "Hello Bob"),
        ("<script>alert('xss')</script>", "Hello &lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"),
        ("  ", "Hello Guest"),
        ("A" * (MAX_USERNAME_LEN + 50), "Hello Guest"), # Too long
    ]

    for i, (input_str, _) in enumerate(test_cases):
        print(f"--- Test Case {i+1} ---")
        printable_input = input_str if len(input_str) < 50 else input_str[:50] + "..."
        print(f"Input: \"{printable_input.replace(chr(10), chr(92)+'n')}\"")
        
        request_stream = io.StringIO(input_str)
        response_stream = io.StringIO()
        
        http_hello_page(request_stream, response_stream)
        
        output_str = response_stream.getvalue()
        print(f"Output: \"{output_str}\"")
        print()

if __name__ == "__main__":
    main()