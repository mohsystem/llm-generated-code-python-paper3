from flask import Flask, request, redirect, url_for, make_response, escape
import os
import secrets

# In a real application, never hardcode credentials.
# CWE-798: Use of Hard-coded Credentials
# Use a secure identity provider and retrieve secrets from a vault or environment variables.
# This example uses plaintext comparison for simplicity, but production systems
# MUST use a strong, salted hashing algorithm like Argon2, scrypt, or PBKDF2.
# CWE-759: Use of a One-Way Hash without a Salt
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "password")

app = Flask(__name__)

# It's recommended to set a secret key for session management, even if not used directly here.
app.secret_key = secrets.token_hex(16)

def get_login_form(error_message=None):
    """Returns the HTML for the login form."""
    error_html = ""
    if error_message:
        # Rule #1: Sanitize output to prevent XSS (CWE-79)
        error_html = f"<p style='color:red;'>{escape(error_message)}</p>"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
    </head>
    <body>
        <h1>Login</h1>
        {error_html}
        <form method="post" action="/login">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    """
    return html

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles the login process."""
    if request.method == 'POST':
        # Rule #1: Validate input
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if not username or not password:
            return get_login_form("Username and password are required."), 400

        # In a real app, use a constant-time comparison for security.
        is_user_valid = secrets.compare_digest(username, ADMIN_USERNAME)
        is_pass_valid = secrets.compare_digest(password, ADMIN_PASSWORD)
        
        if is_user_valid and is_pass_valid:
            # Successful login, redirect to admin page
            return redirect(url_for('admin_page'))
        else:
            # Failed login, show form again with an error
            return get_login_form("Invalid username or password."), 401
    
    # For GET request, just show the login form
    return get_login_form()

@app.route('/admin')
def admin_page():
    """A protected admin page."""
    response = make_response("<h1>Welcome, Admin!</h1>")
    # Add security headers
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == '__main__':
    # For production, use a proper WSGI server like Gunicorn or uWSGI and run behind a reverse proxy.
    # Production systems MUST use HTTPS.
    print("Server starting on http://localhost:8080")
    print("--- Test Cases ---")
    print("1. View login form: curl http://localhost:8080/login")
    print("2. Successful login (will get a 302 redirect): curl -i -L -d \"username=admin&password=password\" http://localhost:8080/login")
    print("3. Failed login (wrong password): curl -i -d \"username=admin&password=wrong\" http://localhost:8080/login")
    print("4. Failed login (wrong username): curl -i -d \"username=user&password=password\" http://localhost:8080/login")
    print("5. Access admin page after successful login: Follow the redirect from test case #2.")
    app.run(host='0.0.0.0', port=8080, debug=False)