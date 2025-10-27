import secrets
from flask import Flask, request, redirect, url_for, session, make_response, escape

# To run: pip install Flask
app = Flask(__name__)
# In a real app, this should be a long, random, secret string, loaded from a config file.
app.secret_key = secrets.token_hex(32)

# In-memory user store. Use a database with hashed passwords in a real app.
USERS = {
    'user': {'password': 'password123', 'role': 'USER'},
    'admin': {'password': 'adminpass', 'role': 'ADMIN'}
}

# 1. Index function (GET)
@app.route('/')
def index():
    if 'username' in session:
        username = escape(session['username'])
        return f"<h1>Welcome, {username}!</h1><p><a href='/user'>User Page</a></p><p><a href='/logout'>Logout</a></p>"
    return "<h1>Welcome!</h1><p>Please <a href='/login'>login</a>.</p>"

# 2. Login function (GET)
@app.route('/login', methods=['GET'])
def login():
    if 'username' in session:
        return redirect(url_for('index'))
    
    # Generate CSRF token for the login form
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

    return f"""
        <form action="/do_login" method="post">
            <h2>Login</h2>
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password"><br>
            <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
            <br><input type="submit" value="Login">
        </form>
    """

# 3. do_login function (POST)
@app.route('/do_login', methods=['POST'])
def do_login():
    # CSRF Protection
    form_token = request.form.get('csrf_token')
    session_token = session.pop('csrf_token', None) # Use token once
    if not session_token or form_token != session_token:
        return "Forbidden: Invalid CSRF Token.", 403

    username = request.form.get('username')
    password = request.form.get('password')

    user_data = USERS.get(username)
    # In a real app, use a secure password verification function like werkzeug.security.check_password_hash
    if user_data and user_data['password'] == password:
        session['username'] = username
        session['role'] = user_data['role']
        # Regenerate CSRF token after login to prevent session fixation
        session['csrf_token'] = secrets.token_hex(16)
        return redirect(url_for('index'))
    else:
        return "Invalid credentials. <a href='/login'>Try again</a>.", 401

# 4. user_page function (GET)
@app.route('/user')
def user_page():
    if 'username' in session:
        username = escape(session.get('username', 'Guest'))
        role = escape(session.get('role', 'None'))
        return f"<h1>User Page</h1><p>Hello, {username}. Your role is {role}.</p><p><a href='/'>Home</a></p>"
    return redirect(url_for('login'))

# 5. admin_page function (GET)
@app.route('/admin')
def admin_page():
    if 'username' in session and session.get('role') == 'ADMIN':
        return "<h1>Admin Page</h1><p>Welcome, administrator!</p><p><a href='/'>Home</a></p>"
    elif 'username' in session:
        return "<h1>403 Forbidden</h1><p>You do not have access to this page.</p>", 403
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    print("Server starting on http://127.0.0.1:8080")
    print("--- Test Cases ---")
    print("1. Visit the index page: http://127.0.0.1:8080/")
    print("2. Visit the login page: http://127.0.0.1:8080/login")
    print("3. Login as 'user' with password 'password123' via the form.")
    print("4. After logging in, visit the user page: http://127.0.0.1:8080/user")
    print("5. Try to visit the admin page (will be forbidden): http://127.0.0.1:8080/admin")
    print("   Then, logout and log in as 'admin' with password 'adminpass' to access it.")
    app.run(host='0.0.0.0', port=8080, debug=False)