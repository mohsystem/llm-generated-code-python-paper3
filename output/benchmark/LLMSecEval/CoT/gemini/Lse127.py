import io
import html

def http_hello_page(request, response):
    """
    Reads a username from a request stream, constructs a "Hello [username]" message,
    and writes it to a response stream. The username is sanitized to prevent XSS.

    :param request: A file-like object for reading the request (e.g., io.StringIO).
    :param response: A file-like object for writing the response (e.g., io.StringIO).
    """
    try:
        # Read the username from the request stream.
        # .strip() removes leading/trailing whitespace, including the newline character.
        username = request.readline().strip()
        if not username:
            username = "" # Treat empty line as empty username

        # Sanitize the username to prevent XSS vulnerabilities using the standard library.
        sanitized_username = html.escape(username)

        # Construct the response.
        hello_response = f"Hello {sanitized_username}"

        # Write the response to the response stream.
        response.write(hello_response)

    except Exception as e:
        # In a real application, log the error appropriately.
        print(f"An error occurred: {e}")

# Main block for test cases
if __name__ == "__main__":
    test_cases = [
        ("Alice", "Hello Alice"),
        ("<script>alert('xss')</script>", "Hello &lt;script&gt;alert('xss')&lt;/script&gt;"),
        ("Bob & Carol", "Hello Bob &amp; Carol"),
        ("Mr. \"O'Malley\"", "Hello Mr. &quot;O'Malley&quot;"),
        ("", "Hello ")
    ]

    for i, (test_input, expected_output) in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        print(f"Input: \"{test_input}\"")

        # Use io.StringIO to simulate file streams in memory.
        request_stream = io.StringIO(test_input + '\n') # Add newline as readline expects it
        response_stream = io.StringIO()

        http_hello_page(request_stream, response_stream)
        actual_output = response_stream.getvalue()

        print(f"Expected: \"{expected_output}\"")
        print(f"Actual  : \"{actual_output}\"")
        print(f"Result  : {'PASS' if expected_output == actual_output else 'FAIL'}")
        print("--------------------")