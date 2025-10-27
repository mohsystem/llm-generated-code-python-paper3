import html
import io

# Define a reasonable maximum length for a username
MAX_USERNAME_LENGTH = 256

def http_hello_page(request, response):
    """
    Reads a username from a request stream, validates it, and writes a secure
    "Hello [username]" greeting to a response stream.

    :param request: A file-like object for reading the request.
    :param response: A file-like object for writing the response.
    """
    try:
        # Read the username, assuming one line of input.
        # Use readline() to avoid reading an excessively large request body.
        username = request.readline(MAX_USERNAME_LENGTH + 2) # Read a bit extra to detect overflow

        # 1. Security: Validate input length.
        # If the line is longer than the max length, it's an issue.
        if len(username) > MAX_USERNAME_LENGTH + 1 or (len(username) == MAX_USERNAME_LENGTH + 1 and not username.endswith('\n')):
             response.write("Hello! (Username is too long)")
             return

        # Strip trailing newline characters
        username = username.strip()

        # 2. Security: Sanitize output using Python's built-in HTML escaping.
        # This is the primary defense against Cross-Site Scripting (XSS).
        sanitized_username = html.escape(username)

        # Construct and write the response
        response.write(f"Hello {sanitized_username}")

    except Exception as e:
        # In a real app, log this exception
        try:
            response.write("An error occurred while processing your request.")
        except Exception:
            pass # Ignore errors on the error-writing attempt

def main():
    # Test cases
    test_inputs = [
        # Test Case 1: Normal valid username
        "Alice",
        # Test Case 2: XSS attack attempt
        "<script>alert('xss')</script>",
        # Test Case 3: Input length violation
        "A" * 300,
        # Test Case 4: Empty username
        "",
        # Test Case 5: Username with special characters that need encoding
        "Bob&Eve"
    ]

    for i, test_input in enumerate(test_inputs):
        print(f"--- Test Case {i + 1} ---")
        print(f"Input: {test_input}")

        # Use io.StringIO to simulate file streams in memory
        request_stream = io.StringIO(test_input + "\n") # Add newline as readline() expects it
        response_stream = io.StringIO()

        http_hello_page(request_stream, response_stream)
        
        print(f"Output: {response_stream.getvalue()}")
        print()

if __name__ == "__main__":
    main()