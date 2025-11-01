import os
import secrets
from flask import Flask, session, escape, request

# It is recommended to install pyopenssl for the adhoc ssl context
# pip install Flask pyopenssl

app = Flask(__name__)

# Rules#15: Never hard code passwords or secrets.
# Read the secret key from an environment variable.
# For development, a new random key is generated on each run.
# In production, this MUST be a stable, securely stored value.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

# Enforce secure session cookie attributes
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

@app.route("/")
def index():
    """Provides navigation for testing."""
    return """
    <h1>Flask Session Example</h1>
    <a href="/login_test">1. Set Session Data (Login)</a><br>
    <a href="/info">2. Get User Info</a><br>
    <a href="/logout">3. Clear Session Data (Logout)</a>
    """

@app.route("/login_test")
def login_test():
    """A test route to populate session data."""
    # In a real application, this data would come from a database after authentication.
    session['username'] = 'testuser'
    session['email'] = 'test@example.com'
    session['ssn'] = '999-99-9999' # Sensitive data
    return "Session data set. <a href='/info'>Click to view info</a>"

@app.route("/info")
def info():
    """
    Displays user information from the session.
    """
    # Rules#14: Input validation. Check if required keys exist in the session.
    required_keys = ['username', 'email', 'ssn']
    if not all(key in session for key in required_keys):
        # Rules#23: Do not leak internal details. Return a generic error.
        return "User information not found in session. Please log in.", 401

    username = session.get('username')
    email = session.get('email')
    ssn = session.get('ssn') # Rules#22: Be cautious with logging this data.

    # Prevent XSS by escaping all data retrieved from the session.
    safe_username = escape(username)
    safe_email = escape(email)
    # SSN is sensitive; display it cautiously. Here we escape it for safety.
    safe_ssn = escape(ssn)

    # Rules#21: Sensitive data handling. Do not log this response.
    return f"Username: {safe_username}, Email: {safe_email}, SSN: {safe_ssn}"

@app.route("/logout")
def logout():
    """Clears the session."""
    session.clear()
    return "Session cleared. <a href='/'>Go to home</a>"


def main():
    """
    Main function to run the Flask application.
    Includes test case descriptions.
    """
    # Note: To run this, you need to install Flask and pyopenssl:
    # pip install Flask pyopenssl
    
    # Rules#18: Enforce TLS. Using 'adhoc' creates a temporary self-signed certificate
    # for development. In production, use a proper certificate from a CA.
    # The 'adhoc' context requires the 'pyopenssl' package.
    print("Starting Flask web server...")
    print("Navigate to https://127.0.0.1:5000 in your browser.")
    print("\n--- Test Cases ---")
    print("1. Access /info before login: Go to https://127.0.0.1:5000/info")
    print("   Expected: 'User information not found...' message with a 401 status.")
    print("2. Set session data: Go to https://127.0.0.1:5000/login_test")
    print("   Expected: 'Session data set.' message.")
    print("3. Access /info after login: Go to https://127.0.0.1:5000/info")
    print("   Expected: 'Username: testuser, Email: test@example.com, SSN: 999-99-9999'")
    print("4. Log out: Go to https://127.0.0.1:5000/logout")
    print("   Expected: 'Session cleared.' message.")
    print("5. Access /info after logout: Go to https://127.0.0.1:5000/info")
    print("   Expected: 'User information not found...' message with a 401 status.")
    
    # Running with debug=False is a secure default for production.
    # We use ssl_context to run over HTTPS, which is required for secure cookies.
    app.run(ssl_context="adhoc", debug=False)

if __name__ == '__main__':
    main()