import secrets
from flask import Flask, request, session, redirect, url_for, escape, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

# --- Application Setup ---
app = Flask(__name__)
# In a real app, this key should be a long, random, and securely stored secret.
# For demonstration, we generate one on startup.
app.config['SECRET_KEY'] = secrets.token_hex(16)

# --- User Store (In-memory database for demonstration) ---
# In a real application, use a proper database.
# Passwords should never be stored in plain text. We store a hash.
# Rule #5, #8: Using a strong hash with a unique salt for each user.
# The salt is automatically handled by generate_password_hash.
# Rule #7: Avoid hardcoding. Here it's for demonstration. In production,
# this data would come from a database, and initial admin users might be
# seeded via secure scripts or environment variables.
USERS = {
    'admin': generate_password_hash('password123'),
    'user': generate_password_hash('Password!@#'),
    'testuser1': generate_password_hash('my$ecret'),
    'testuser2': generate_password_hash('an0therTest'),
    'testuser3': generate_password_hash('finalp@ss'),
}

# --- HTML Templates ---
INDEX_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Index</title></head>
<body>
    <h1>Welcome</h1>
    <p>Please <a href="{{ url_for('do_login') }}">login</a> to continue.</p>
</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
    <form method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

SECRET_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Secret Page</title></head>
<body>
    <h1>Secret settings</h1>
    <p>Welcome, {{ username }}!</p>
    <p><a href="{{ url_for('logout') }}">Logout</a></p>
</body>
</html>
"""

# --- Routes ---

@app.route('/')
def index():
    """Index page with a link to the login page."""
    return render_template_string(INDEX_PAGE)

@app.route('/login', methods=['GET', 'POST'])
def do_login():
    """Login function: shows form on GET, processes login on POST."""
    error = None
    if request.method == 'POST':
        # Rule #1: Validate and sanitize input. Here we get it from the form.
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            error = 'Username and password are required.'
        elif username in USERS and check_password_hash(USERS.get(username, ''), password):
            # Login successful: store username in session
            session['username'] = username
            return redirect(url_for('secret'))
        else:
            error = 'Invalid username or password.'
    
    return render_template_string(LOGIN_PAGE, error=error)

@app.route('/secret')
def secret():
    """Secret page, accessible only to logged-in users."""
    if 'username' in session:
        # Rule #10: Escape user-controlled data to prevent XSS
        safe_username = escape(session['username'])
        return render_template_string(SECRET_PAGE, username=safe_username)
    else:
        # Not logged in, redirect to login page
        return redirect(url_for('do_login'))

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Main method for testing.
    # In a production environment, use a proper WSGI server like Gunicorn or uWSGI.
    print("Starting Flask web server...")
    print("Navigate to http://127.0.0.1:5000")
    print("\n--- Test Cases ---")
    print("1. Visit http://127.0.0.1:5000/ - Should show the index page.")
    print("2. Click 'login' link - Should show the login form.")
    print("3. Try logging in with incorrect credentials (e.g., 'admin'/'wrongpass') - Should show an error.")
    print("4. Try logging in with correct credentials (e.g., 'admin'/'password123') - Should redirect to the secret page.")
    print("5. Directly visit http://127.0.0.1:5000/secret without logging in - Should redirect to login.")
    print("After logging in, visiting http://127.0.0.1:5000/logout should log you out.")
    
    app.run(host="0.0.0.0", port=5000)