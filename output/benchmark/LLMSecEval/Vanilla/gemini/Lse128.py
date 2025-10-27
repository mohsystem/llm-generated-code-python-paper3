import io

def http_hello_page(request, response):
    """
    Reads a username from a request stream and writes a greeting to a response stream.
    Assumes the request body is in the format "username=[some_name]".
    :param request: A file-like object for reading the request.
    :param response: A file-like object for writing the response.
    """
    request_line = request.readline()
    username = "guest"  # Default username

    if request_line and request_line.startswith("username="):
        parts = request_line.split("=", 1)
        if len(parts) == 2:
            username = parts[1].strip()
    
    response_body = f"hello {username}"
    response.write(response_body)
    response.flush()

# Main block with 5 test cases
if __name__ == "__main__":
    def test(request_body, expected_response):
        # Simulate request and response streams using in-memory io.StringIO
        request_stream = io.StringIO(request_body)
        response_stream = io.StringIO()

        # Call the function
        http_hello_page(request_stream, response_stream)
        
        # Rewind the response stream to the beginning to read its content
        response_stream.seek(0)
        actual_response = response_stream.read()
        
        # Print results
        print(f'Request: "{request_body}"')
        print(f'Expected: "{expected_response}"')
        print(f'Actual  : "{actual_response}"')
        print(f"Result  : {'PASS' if expected_response == actual_response else 'FAIL'}")
        print()

    print("--- Python Test Cases ---")

    # Test Case 1: Standard username
    test("username=Alice", "hello Alice")
    
    # Test Case 2: Username with spaces
    test("username=  Bob  ", "hello Bob")
    
    # Test Case 3: Empty username
    test("username=", "hello ")
    
    # Test Case 4: Malformed request (doesn't start with "username=")
    test("user=Charlie", "hello guest")
    
    # Test Case 5: Empty request
    test("", "hello guest")