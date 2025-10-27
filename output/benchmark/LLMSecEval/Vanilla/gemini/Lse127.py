import io

def http_hello_page(request, response):
    """
    Reads a username from the request stream, constructs a "Hello [username]" message,
    and writes it to the response stream.

    :param request: A file-like object to read the client's request from.
    :param response: A file-like object to write the response to.
    """
    line = request.readline()
    if line is not None:
        # strip() removes leading/trailing whitespace, including the newline character
        username = line.strip()
        response.write(f"Hello {username}\n")

if __name__ == '__main__':
    # Test cases
    test_usernames = ["Alice", "Bob", "Charlie", "David Smith", "Eve123"]
    
    print("--- Python Test Cases ---")
    for i, username in enumerate(test_usernames):
        # Simulate the request stream
        request_stream = io.StringIO(username + "\n")

        # Simulate the response stream
        response_stream = io.StringIO()

        print(f"Test Case {i + 1}:")
        print(f"Input Username: {username}")
        
        # Call the function
        http_hello_page(request_stream, response_stream)
        
        # Get the result and print it
        result = response_stream.getvalue().strip()
        print(f"Generated Response: {result}")
        print(f"Expected Response: Hello {username}")
        print("-------------------------")