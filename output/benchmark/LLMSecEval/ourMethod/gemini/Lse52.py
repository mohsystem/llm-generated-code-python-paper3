import os
import secrets
from flask import Flask, request, redirect, url_for, session, flash, render_template_string

# 1. Problem understanding: Create a Flask web app with index, login, and a protected secret page.
#    - /: Welcome page with a link to login.
#    - /login: Form for username/password. On POST, validates credentials.
#    - /secret: Protected page, only for logged-in users.
#    - /logout: Clears the session.
# 2. Security requirements & mitigation:
#    - Rules#7, #35: No hardcoded secrets. Load credentials and secret key from environment variables.
#    - Rules#1, #5, #34: Validate input. Check for presence and reasonable length of username/password.
#    - Rule#2: Use allow-list for login (credentials must match).
#    - Rule#43: Return generic error messages on login failure to prevent user enumeration.
#    - Use `secrets.compare_digest` to prevent timing attacks on password comparison.
#    - Use Flask's session management, which relies on a strong secret key for signed cookies.
#    - Jinja2 auto-escaping (default in Flask) prevents XSS from session data rendered in templates.
#    - Redirects are to hardcoded internal URLs, which is safe and prevents open redirect vulnerabilities.

# Initialize Flask App
app = Flask(__name__)

# --- Configuration and Secret Management ---
# Rule #7, #35: Never hardcode secrets. Read them from external configuration (environment variables).
# The application will fail to start if these are not set, which is a secure default (fail-closed).
try:
    app.secret_key = os.environ['APP_SECRET_KEY']
    VALID_USERNAME = os.environ['APP_USER']
    VALID_PASSWORD = os.environ['APP_PASSWORD']
except KeyError as e:
    raise RuntimeError(f"Required environment variable {e} not set. "
                       "Please set APP_SECRET_KEY, APP_USER, and APP_PASSWORD.") from e

# --- Templates ---
# For simplicity, templates are defined as strings. In a real application,
# these would be in separate .html files.

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Index</title>
</head>
<body>
    <h1>Welcome to the Application</h1>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul class=flashes>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    {% if 'username' in session %}
        <p>You are logged in as <strong>{{ session.username | e }}</strong>.</p>
        <a href="{{ url_for('secret_page') }}">Go to Secret Page</a><br>
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <p>You are not logged in.</p>
        <a href="{{ url_for('login') }}">Login</a>
    {% endif %}
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <ul class=flashes>
        {% for category, message in messages %}
          <li class="{{ category }}" style="color: red;">{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <form method="post" action="{{ url_for('do_login') }}">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" required maxlength="100" autocomplete="username"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required maxlength="100" autocomplete="current-password"><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

SECRET_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secret Page</title>
</head>
<body>
    <h1>Secret settings</h1>
    <p>Welcome, <strong>{{ session.username | e }}</strong>! This is a protected page.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# --- Routes ---

@app.route('/')
def index():
    """Displays the index page."""
    return render_template_string(INDEX_TEMPLATE)

@app.route('/login', methods=['GET'])
def login():
    """Displays the login form."""
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/do_login', methods=['POST'])
def do_login():
    """Processes the login attempt."""
    # Rule #1, #5, #34: Treat all input as untrusted and validate it.
    username = request.form.get('username')
    password = request.form.get('password')

    # Validate for presence and reasonable length.
    if not username or not password or len(username) > 100 or len(password) > 100:
        flash('Invalid input.', 'error')
        return redirect(url_for('login'))

    # Rule #2: Use allow lists. Check against known credentials.
    # Use `secrets.compare_digest` for constant-time comparison to mitigate timing attacks.
    is_user_valid = secrets.compare_digest(username, VALID_USERNAME)
    is_pass_valid = secrets.compare_digest(password, VALID_PASSWORD)

    if is_user_valid and is_pass_valid:
        # If credentials are correct, set the username in the session.
        session['username'] = username
        return redirect(url_for('secret_page'))
    else:
        # Rule #43: Return generic, non-revealing error messages.
        flash('Invalid username or password.', 'error')
        return redirect(url_for('login'))

@app.route('/secret')
def secret_page():
    """Displays the secret page, accessible only to logged-in users."""
    if 'username' not in session:
        flash('You must be logged in to view this page.', 'error')
        return redirect(url_for('login'))
    return render_template_string(SECRET_TEMPLATE)

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

def main():
    """
    Main function to run the Flask application and provide test cases.
    For this web application, test cases are manual steps for the user to perform.
    """
    print("="*60)
    print("Starting Flask Web Server")
    print("="*60)
    print("IMPORTANT: Before running, set the following environment variables in your shell:")
    # Use secrets.token_hex to generate a cryptographically strong key
    print(f"  export APP_SECRET_KEY='{secrets.token_hex(16)}'")
    print("  export APP_USER='admin'")
    print("  export APP_PASSWORD='password123'")
    print("="*60)
    print("Manual Test Cases to Perform:")
    print("1. Access Index Page: Open a web browser to http://127.0.0.1:5000/")
    print("   - Expected: Welcome page with a 'Login' link.")
    print("2. Access Secret Page (Unauthenticated): Go to http://127.0.0.1:5000/secret")
    print("   - Expected: Redirect to the login page with a message 'You must be logged in...'.")
    print("3. Failed Login Attempt: On the login page, enter incorrect credentials and submit.")
    print("   - Expected: The page reloads with an 'Invalid username or password' error.")
    print("4. Successful Login: On the login page, enter the correct credentials and submit.")
    print("   - Expected: Redirect to the '/secret' page with a welcome message.")
    print("5. Logout: On the secret page, click the 'Logout' link.")
    print("   - Expected: Redirect to the index page with a 'You have been logged out' message.")
    print("   - Verification: Attempting to access /secret again should fail.")
    print("="*60)

    # Note: debug=True is for development only and should NEVER be used in production.
    # It enables an interactive debugger which can be a major security risk.
    # In a production environment, use a proper WSGI server like Gunicorn or uWSGI.
    app.run(host='127.0.0.1', port=5000, debug=False)

if __name__ == '__main__':
    # The main() function will raise a RuntimeError if environment variables are missing.
    main()