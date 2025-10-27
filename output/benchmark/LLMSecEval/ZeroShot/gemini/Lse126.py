import html

def http_hello_page(username: str) -> str:
    """
    Simulates handling an HTTP request for /hello.
    It takes a username, securely escapes it to prevent XSS,
    and constructs an HTML response.

    Args:
        username: The username read from the request body.

    Returns:
        A string containing the full HTML page response.
    """
    # The server reads the request body into the username variable.
    # We receive it as a parameter.

    # Securely escape the username to prevent XSS vulnerabilities using the standard library.
    sanitized_username = html.escape(username)

    # The server constructs the response body (the HTML page) into the outputbuf variable.
    outputbuf = f"<html><body><h1>Hello, {sanitized_username}!</h1></body></html>"

    # In a real server, this buffer would be written to the response stream.
    # The function returns the response body.
    return outputbuf

def main():
    """ Main function with test cases. """
    test_cases = [
        "Alice",
        "Bob Smith",
        "",
        "<script>alert('XSS Attack!')</script>",
        "O'Malley & Sons"
    ]

    print("--- Python Test Cases ---")
    for i, test_case in enumerate(test_cases):
        print(f"Test Case {i+1}:")
        print(f"Input:  {test_case}")
        response = http_hello_page(test_case)
        print(f"Output: {response}\n")

if __name__ == "__main__":
    main()