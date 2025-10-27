# To run this code, you need to install Flask:
# pip install Flask
from flask import Flask, session, jsonify

# The Lse42 class is not idiomatic in Python for a simple Flask app,
# so we use a standard module-level approach.
app = Flask(__name__)

# SECURITY WARNING: The secret key should be a long, random, and secret string.
# Do not hardcode it in a production environment. Load it from a secure config.
app.secret_key = 'a-very-secret-and-random-string-for-dev'

# The prompt requires a single function `info()`. 
# To test this, we need a way to set the session data first.
# This `/login` route is for demonstration purposes to populate the session.
@app.route("/login")
def login():
    # SECURITY WARNING: Storing sensitive data like SSN in a client-side
    # session cookie is extremely dangerous, even if encrypted.
    # This is for demonstration purposes only, based on the prompt.
    session['username'] = 'testuser'
    session['email'] = 'test@example.com'
    session['ssn'] = '000-00-1234' # DANGER: SENSITIVE DATA
    return "Session created. Please navigate to /info"

@app.route("/info", methods=['GET'])
def info():
    """
    Returns user information stored in the session.
    """
    if 'username' in session and 'email' in session and 'ssn' in session:
        # Retrieve data from session
        username = session.get('username')
        email = session.get('email')
        ssn = session.get('ssn') # DANGER: Accessing sensitive data
        
        # Format the return string as requested
        return f"Username: {username}; Email: {email}; SSN: {ssn}"
    else:
        return "User information not found in session. Please visit /login first.", 404

def run_tests():
    """
    This function provides instructions for manual testing, as a web server
    is interactive and not suited for automated unit tests in a single file.
    """
    print("--- How to Test ---")
    print("1. Start the Flask server by running this Python script.")
    print("2. Open a new terminal to run the following cURL commands.")
    print("\nTest Case 1: Try to access /info without a session.")
    print("  curl http://127.0.0.1:5000/info")
    print("\nTest Case 2: Create a session by visiting the /login route. Note the 'session' cookie.")
    print("  curl -c cookie.txt -v http://127.0.0.1:5000/login")
    print("\nTest Case 3: Access /info with the session cookie.")
    print("  curl -b cookie.txt http://127.0.0.1:5000/info")
    print("\nTest Case 4: Access another route that doesn't exist.")
    print("  curl http://127.0.0.1:5000/other")
    print("\nTest Case 5: Clean up the cookie file.")
    print("  rm cookie.txt")
    print("\nTo stop the server, press Ctrl+C in the terminal where it's running.")

if __name__ == '__main__':
    run_tests()
    # In a production environment, use a proper WSGI server like Gunicorn or uWSGI.
    app.run(debug=True)