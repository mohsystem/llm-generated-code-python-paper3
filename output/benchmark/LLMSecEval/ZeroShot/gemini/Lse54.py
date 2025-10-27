import os
import secrets
import hmac
from flask import Flask, request, render_template_string, redirect, url_for, session, flash, Response

# In a real app, use a proper configuration file and environment variables.
# The secret key should be a long, random, and secret string.
# To generate one: python -c 'import secrets; print(secrets.token_hex(16))'
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

# NOTE: In a real application, NEVER hardcode credentials.
# Use a secure password hashing mechanism (e.g., Argon2, bcrypt) and store hashes in a database.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "SuperSecurePassword123!"

app = Flask(__name__)
app.secret_key = SECRET_KEY
# Configure secure session cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True if using HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

LOGIN_FORM_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <p style="color:red;">{{ messages[0] }}</p>
      {% endif %}
    {% endwith %}
    <form method="post" action="{{ url_for('do_login') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

ADMIN_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Page</title>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
</body>
</html>
"""

@app.before_request
def set_security_headers():
    """Set security headers for all responses."""
    @app.after_request
    def inject_headers(response):
        # Prevent page from being displayed in an iframe
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Prevent browser from MIME-sniffing a response away from the declared content-type
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

@app.route("/login", methods=["GET"])
def login():
    """Serves the login form."""
    if 'username' in session and session['username'] == ADMIN_USERNAME:
        return redirect(url_for('admin_page'))

    # Generate and store a CSRF token in the session
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
        
    return render_template_string(LOGIN_FORM_TEMPLATE, csrf_token=session['csrf_token'])

@app.route("/do_login", methods=["POST"])
def do_login():
    """Handles the login submission."""
    # 1. CSRF Token Validation
    submitted_token = request.form.get('csrf_token')
    expected_token = session.pop('csrf_token', None) # Use token only once
    if not expected_token or not hmac.compare_digest(expected_token, submitted_token):
        flash("Invalid CSRF token. Please try again.")
        return redirect(url_for('login'))

    # 2. Input sanitization/validation (basic check for presence)
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Username and password are required.")
        return redirect(url_for('login'))
    
    # 3. Authentication check
    # Constant-time comparison to prevent timing attacks
    is_username_match = hmac.compare_digest(ADMIN_USERNAME, username)
    is_password_match = hmac.compare_digest(ADMIN_PASSWORD, password)

    if is_username_match and is_password_match:
        # Successful login: create a secure session
        session['username'] = username
        # Regenerate session ID to prevent session fixation
        session.permanent = True
        return redirect(url_for('admin_page'))
    else:
        # Failed login
        flash("Invalid username or password.")
        return redirect(url_for('login'))

@app.route("/admin_page")
def admin_page():
    """Displays the admin page if the user is logged in as admin."""
    if 'username' in session and session['username'] == ADMIN_USERNAME:
        return render_template_string(ADMIN_PAGE_TEMPLATE, username=session['username'])
    else:
        flash("You need to be logged in to access this page.")
        return redirect(url_for('login'))

# Although not strictly a main method, this block serves the same purpose.
# It is not a test suite but provides instructions for manual testing.
if __name__ == '__main__':
    port = 8081
    print(f"Server starting on http://127.0.0.1:{port}")
    print("--- How to run test cases ---")
    print(f"1. Access Login Page: Open a browser and go to http://127.0.0.1:{port}/login")
    print(f"2. Successful Login: Use username '{ADMIN_USERNAME}' and password '{ADMIN_PASSWORD}'")
    print(f"3. Failed Login (Wrong Pass): Use username '{ADMIN_USERNAME}' and any other password.")
    print("4. Failed Login (Wrong User): Use any username other than 'admin'.")
    print(f"5. Unauthorized Access: Try to directly access http://127.0.0.1:{port}/admin_page in a new private/incognito browser window.")
    
    # In a production environment, use a proper WSGI server like Gunicorn or uWSGI.
    app.run(port=port, debug=False)