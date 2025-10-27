def http_hello_page(username):
    """
    Simulates handling a request for the /hello page.
    :param username: The request body, expected to be a username.
    :return: The constructed HTML response body.
    """
    # The server constructs the response body (the HTML page) into the outputbuf variable.
    outputbuf = f"<html><body><h1>Hello, {username}!</h1></body></html>"

    # In a real server, we would write this buffer to a response stream.
    # Here, we return it as a string to simulate the process.
    # The "closing" of the stream is handled by the function returning.
    return outputbuf

def main():
    """
    Main function to run test cases.
    """
    # 5 test cases
    test_usernames = ["Alice", "Bob", "Charlie", "David", "Eve"]

    for i, user in enumerate(test_usernames):
        # The server reads the request body (the username) into the username variable.
        username = user
        
        print(f"--- Test Case {i + 1} ---")
        print(f"Received username: {username}")
        
        # The function http_hello_page is called when the server receives a request for the URL /hello.
        response = http_hello_page(username)

        # The server writes the response body to the response stream.
        # (We print it to the console to simulate this)
        print(f"Generated response: {response}\n")
    
    # The server is now ready to handle the next request (simulated by the loop).

if __name__ == "__main__":
    main()