import io
import html

def http_hello_page(request, response):
    """
    Reads a username from a request stream, sanitizes it, and writes a
    "hello [username]" message to the response stream.

    Args:
        request: A readable text stream (like a file object).
        response: A writable text stream (like a file object).
    """
    try:
        # Read the username. Assume it's the first line.
        # .strip() removes leading/trailing whitespace, including the newline character.
        username = request.readline().strip()

        # Sanitize the username to prevent XSS attacks using the standard library.
        sanitized_username = html.escape(username)

        # Construct the response
        response_body = f"hello {sanitized_username}"

        # Write the response to the output stream
        response.write(response_body)

    except Exception as e:
        # In a real application, handle exceptions more gracefully.
        print(f"An error occurred: {e}")


def main():
    """Main function to run test cases."""
    # Test cases: (input_username, expected_output)
    test_cases = [
        ("Alice", "hello Alice"),                                       # Test Case 1: Simple
        ("Bob Smith", "hello Bob Smith"),                               # Test Case 2: With space
        ("", "hello "),                                                 # Test Case 3: Empty
        ("<script>alert('XSS')</script>", "hello &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"), # Test Case 4: XSS
        ("User with \"&'<> special chars", "hello User with &quot;&amp;&#x27;&lt;&gt; special chars") # Test Case 5: Special chars
    ]

    print("--- Running Python Tests ---")
    for i, (username, expected) in enumerate(test_cases, 1):
        # Simulate request and response streams using in-memory StringIO
        request_stream = io.StringIO(username + "\n") # Add newline as readline() expects it
        response_stream = io.StringIO()

        # Call the function
        http_hello_page(request_stream, response_stream)

        # Get the actual output from the response stream
        actual = response_stream.getvalue()

        # Compare and print results
        print(f"Test Case {i}:")
        print(f"  Input:    \"{username}\"")
        print(f"  Expected: \"{expected}\"")
        print(f"  Actual:   \"{actual}\"")
        print(f"  Result:   {'PASSED' if expected == actual else 'FAILED'}")
        print()

if __name__ == "__main__":
    main()