import hashlib
import os
import hmac
from flask import Flask, request, redirect, url_for, session, render_template_string

# Note: In a production environment, never hardcode the secret key.
# Load it from an environment variable or a secure configuration file.
app = Flask(__name__)
app.secret_key = os.urandom(24)

# In-memory user store. In a real application, use a database.
# Passwords are pre-hashed for this example.
# Use the included `hash_new_password` function to generate new entries.
def hash_new_password(password):
    """Hashes a password with a new salt."""
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + pwd_hash

# A helper to check the password
def check_password(stored_password_with_salt, provided_password):
    """Checks a provided password against a stored salt and hash."""
    if not stored_password_with_salt or not provided_password:
        return False
    salt = stored_password_with_salt[:16]
    stored_hash = stored_password_with_salt[16:]
    pwd_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
    return hmac.compare_digest(stored_hash, pwd_hash)

# Store the binary hash directly.
USERS = {
    'admin': hash_new_password('password123')
}

# --- Main Login Logic (for testing and application use) ---
def do_login_logic(username, password):
    """
    Checks the username and password against the stored users.
    Returns True on success, False on failure.
    """
    if not username or not password:
        return False
    
    stored_hash = USERS.get(username)
    if not stored_hash:
        # To prevent username enumeration, perform a dummy check
        check_password(hash_new_password('dummy'), password)
        return False

    return check_password(stored_hash, password)

# --- Web Routes ---
@app.route('/')
def index():
    return render_template_string('''
        <html><body>
            <h1>Welcome</h1>
            <p><a href="{{ url_for('login') }}">Login</a></p>
        </body></html>
    ''')

@app.route('/login', methods=['GET'])
def login():
    return render_template_string('''
        <html><body>
            <h2>Login</h2>
            <form method="post" action="{{ url_for('do_login') }}">
              Username: <input type="text" name="username"><br>
              Password: <input type="password" name="password"><br>
              <input type="submit" value="Login">
            </form>
        </body></html>
    ''')
    
@app.route('/do_login', methods=['POST'])
def do_login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if do_login_logic(username, password):
        session['username'] = username
        return redirect(url_for('secret'))
    else:
        return 'Invalid username or password. <a href="/login">Try again</a>.', 401

@app.route('/secret')
def secret():
    if 'username' in session:
        # Jinja2 (used by render_template_string) automatically escapes variables,
        # preventing XSS attacks.
        return render_template_string('<html><body><h1>Secret settings</h1><p>Welcome, {{ user }}!</p></body></html>', user=session['username'])
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    # --- 5 Test Cases for Login Logic ---
    print("--- Running 5 Login Logic Test Cases ---")
    print("1. Correct credentials ('admin', 'password123'):", do_login_logic('admin', 'password123'))
    print("2. Wrong password ('admin', 'wrongpass'):", do_login_logic('admin', 'wrongpass'))
    print("3. Wrong username ('user', 'password123'):", do_login_logic('user', 'password123'))
    print("4. Empty username ('', 'password123'):", do_login_logic('', 'password123'))
    print("5. Empty password ('admin', ''):", do_login_logic('admin', ''))
    print("----------------------------------------\n")
    
    # --- Start Web Server ---
    print("Server starting on http://127.0.0.1:5000")
    app.run(debug=False)