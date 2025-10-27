# NOTE: To run this Python code, you need the Flask framework.
# Install it using pip:
# pip install Flask
#
# To run, execute the script from your terminal:
# python your_script_name.py
# The server will start on http://127.0.0.1:5000

import os
from flask import Flask, session, jsonify

# Create a Flask application instance
app = Flask(__name__)

# Secure Coding: Set a secret key for session management.
# In a real application, this should be a long, random, and securely stored value,
# not hardcoded. It's often loaded from an environment variable.
app.config['SECRET_KEY'] = os.urandom(24)

@app.route('/info', methods=['GET'])
def info():
    """
    SECURITY WARNING: This code is for demonstration purposes only.
    Exposing sensitive PII like an SSN via an API is extremely insecure.
    Real applications must have strong authentication and authorization.
    The SSN should also be masked.
    """
    # Secure Coding: Check if a user is logged in by verifying a key session variable.
    if 'username' in session:
        # Retrieve data, using .get() with a default value for safety.
        username = session.get('username', 'N/A')
        email = session.get('email', 'N/A')
        # In a real application, the SSN should be masked.
        ssn = session.get('ssn', 'N/A')

        user_data = {
            "username": username,
            "email": email,
            "ssn": ssn
        }
        # Secure Coding: Use jsonify to correctly format JSON and set the Content-Type header.
        # This helps prevent content-sniffing related vulnerabilities.
        return jsonify(user_data)
    else:
        # If the user is not logged in, return an error and a 401 Unauthorized status code.
        return jsonify({"error": "User not authenticated. Please log in."}), 401

# Main block to run the app and tests
if __name__ == '__main__':
    # --- Test Cases ---
    # We use Flask's test_client to simulate requests without running a live server.
    with app.test_client() as client:
        print("--- Running Tests ---")

        # Test Case 1: All user data is present in the session.
        print("\n--- Test Case 1: Valid Session ---")
        with client.session_transaction() as sess:
            sess['username'] = 'jdoe'
            sess['email'] = 'jdoe@example.com'
            sess['ssn'] = '**********' # Masked for security
        response = client.get('/info')
        print(f"Status Code: {response.status_code}")
        print(f"Response Data: {response.get_json()}")
        assert response.status_code == 200
        assert response.get_json()['username'] == 'jdoe'

        # Test Case 2: Some data is missing (ssn).
        print("\n--- Test Case 2: Session with Missing Data ---")
        with client.session_transaction() as sess:
            sess['username'] = 'asmith'
            sess['email'] = 'asmith@example.com'
        response = client.get('/info')
        print(f"Status Code: {response.status_code}")
        print(f"Response Data: {response.get_json()}")
        assert response.status_code == 200
        assert response.get_json()['ssn'] == 'N/A'

        # Test Case 3: User is not logged in (username is missing).
        print("\n--- Test Case 3: Unauthenticated Session ---")
        with client.session_transaction() as sess:
            # Clear any previous session data
            sess.clear()
            sess['email'] = 'hacker@example.com'
        response = client.get('/info')
        print(f"Status Code: {response.status_code}")
        print(f"Response Data: {response.get_json()}")
        assert response.status_code == 401
        assert 'error' in response.get_json()

        # Test Case 4: No session cookie sent at all.
        print("\n--- Test Case 4: No Session at All ---")
        # For this test, we don't create a session_transaction
        response = client.get('/info')
        print(f"Status Code: {response.status_code}")
        print(f"Response Data: {response.get_json()}")
        assert response.status_code == 401

        # Test Case 5: Different valid user.
        print("\n--- Test Case 5: Different Valid User ---")
        with client.session_transaction() as sess:
            sess['username'] = 'test.user'
            sess['email'] = 'test.user@example.com'
            sess['ssn'] = '**********'
        response = client.get('/info')
        print(f"Status Code: {response.status_code}")
        print(f"Response Data: {response.get_json()}")
        assert response.status_code == 200
        assert response.get_json()['username'] == 'test.user'

        print("\n--- Tests Complete ---")

    # Start the actual web server
    print("\nStarting server at http://127.0.0.1:5000")
    print("Press CTRL+C to stop the server.")
    app.run(debug=False)