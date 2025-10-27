import html
from flask import Flask

# This is a conceptual demonstration. 
# For a real web application, you would run this with a WSGI server.
# The code below uses Flask to show the decorator pattern as requested.

app = Flask(__name__)

# The decorator @app.route creates a mapping between the URL and the function.
@app.route("/hello/<username>")
def hello(username):
    """
    Returns a string with "Hello" followed by the escaped username.
    The username is passed as an argument from the URL.
    """
    # Rule #1: Sanitize input. html.escape() is the modern equivalent of cgi.escape().
    escaped_username = html.escape(username)
    return f"Hello, {escaped_username}!"

def main():
    """
    Main function with 5 test cases to demonstrate the hello function's behavior
    without running a full web server.
    """
    print("--- Python Test Cases ---")
    
    test_cases = [
        "World",
        "Python",
        "<script>alert('xss')</script>",
        "O'Malley",
        "a&b"
    ]
    
    for case in test_cases:
        # Simulate calling the handler function directly
        with app.test_request_context(f'/hello/{case}'):
            # The 'username' is passed to the hello function by Flask's routing mechanism.
            # Here, we call it directly for demonstration.
            response = hello(case)
            print(f"Input username: {case}")
            print(f"Response: {response}")
            print()

if __name__ == '__main__':
    # The prompt asks for a runnable file, but starting a web server blocks.
    # So we will run the test cases directly via main().
    # To run the actual web server, you would uncomment the line below.
    # app.run(debug=False)
    main()