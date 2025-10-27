# NOTE: This code requires the Flask library.
# Install it using pip: pip install Flask

# Line 1: The first line imports the web application class.
from flask import Flask, escape

# Line 2: An instance of this class will be our WSGI application.
app = Flask(__name__)

# Line 3: A decorator. It tells the application which URL should call the associated function.
@app.route('/')
# Line 4: The function that is called when the user visits the specified URL.
def hello_world():
    # Line 5: Returns the message to the user.
    # The static string is inherently safe. If it included user input,
    # we would use `escape()` to prevent Cross-Site Scripting (XSS) attacks.
    return 'Hello, World!'

def run_tests():
    """Runs 5 test cases against the Flask application context."""
    print("--- Running Python Tests ---")
    client = app.test_client()

    # Test 1: Check response content for the root URL
    response = client.get('/')
    assert response.data == b'Hello, World!', "Test 1 Failed: Incorrect content"
    print("Test 1 Passed: Correct content at /")

    # Test 2: Check status code for the root URL
    assert response.status_code == 200, "Test 2 Failed: Incorrect status code"
    print("Test 2 Passed: Status code is 200 for /")

    # Test 3: Check status code for a non-existent URL
    response = client.get('/nonexistent')
    assert response.status_code == 404, "Test 3 Failed: Should be 404"
    print("Test 3 Passed: Status code is 404 for nonexistent route")

    # Test 4: Check Content-Type header
    response = client.get('/')
    assert 'text/html' in response.content_type, "Test 4 Failed: Incorrect Content-Type"
    print("Test 4 Passed: Content-Type is correct")

    # Test 5: Check that POST method is not allowed
    response = client.post('/')
    assert response.status_code == 405, "Test 5 Failed: POST should not be allowed"
    print("Test 5 Passed: Method POST correctly returns 405")
    
    print("--- Tests Finished ---\n")


if __name__ == '__main__':
    run_tests()
    
    # Line 6: Runs the application.
    # The development server is not for production use.
    # Setting debug=False is crucial for security in any environment
    # other than local development.
    print("Starting Flask server at http://127.0.0.1:5000")
    print("Press Ctrl+C to stop.")
    app.run(host='0.0.0.0', port=5000, debug=False)