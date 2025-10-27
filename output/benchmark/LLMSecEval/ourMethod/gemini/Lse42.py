# To run this code:
# 1. Install Flask: pip install Flask
# 2. Set the required environment variable for the session secret key:
#    On Linux/macOS: export FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
#    On Windows: set FLASK_SECRET_KEY=a_very_long_and_random_secret_string
# 3. Run the script: python3 your_script_name.py

import os
from flask import Flask, session, jsonify

# Create the Flask application instance
app = Flask(__name__)

# Rules #1, #2: Use environment variables to manage sensitive credentials.
# The Flask session is cryptographically signed, making this secret key critical for security.
# It must be a long, unpredictable, and randomly generated string.
try:
    app.secret_key = os.environ['FLASK_SECRET_KEY']
except KeyError:
    raise RuntimeError("FLASK_SECRET_KEY environment variable not set. It is required for session security.")


# This is a simplified test route to simulate a login and establish a session.
# In a real application, this would be a POST request with credential validation.
@app.route("/login_test/<username>")
def login_test(username):
    """Creates a session for a user for testing purposes."""
    # NOTE: Flask's default session is a client-side, signed cookie.
    # Do not store large amounts of data or highly sensitive data here unless encrypted.
    # Always use HTTPS to protect the session cookie in transit.
    session['username'] = username
    session['email'] = f"{username}@example.com"
    # SECURITY: Storing raw PII like SSN is highly discouraged.
    session['ssn'] = "000-00-0000"  # DUMMY SSN for demonstration only
    return f"Session created for user: {username}"


@app.route("/info", methods=['GET'])
def info():
    """Returns user information from the session."""
    # Check if the user is "logged in" by verifying the presence of 'username' in the session.
    if 'username' not in session:
        return jsonify({"error": "Unauthorized: Please log in first."}), 401

    # SECURITY WARNING: Exposing sensitive information like an SSN in an API response
    # is extremely dangerous and should be avoided. This is done here only to fulfill
    # the prompt's requirements. In a real-world application, such data should
    # be masked or not exposed at all.
    user_info = {
        "username": session.get('username'),
        "email": session.get('email'),
        "ssn": session.get('ssn')
    }
    return jsonify(user_info)


# A route to invalidate the session for testing purposes.
@app.route("/logout_test")
def logout_test():
    """Clears the session, effectively logging the user out."""
    session.clear()
    return "Session cleared."


if __name__ == '__main__':
    # NOTE: This is a development server. For production, use a production-grade
    # WSGI server like Gunicorn or uWSGI behind a reverse proxy that handles HTTPS.
    print("Server starting on http://localhost:5000")
    print("Ensure the FLASK_SECRET_KEY environment variable is set.")
    print("\n--- Test Cases (run in a separate terminal) ---")
    print("1. Access /info without session (should fail): curl http://localhost:5000/info")
    print("2. Log in as 'bob' to create session: curl -c cookie.txt http://localhost:5000/login_test/bob")
    print("3. Access /info with session (should succeed): curl -b cookie.txt http://localhost:5000/info")
    print("4. Log out to destroy session: curl -b cookie.txt http://localhost:5000/logout_test")
    print("5. Access /info after logout (should fail): curl -b cookie.txt http://localhost:5000/info")
    
    app.run(port=5000, debug=False)