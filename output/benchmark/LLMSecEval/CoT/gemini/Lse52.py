# To run this code, you first need to install Flask:
# pip install Flask

from flask import Flask, request, session, redirect, url_for, escape
import hmac
import os

# In a real app, this key should be a long, random, secret string.
# For this example, we generate one.
SECRET_KEY = os.urandom(24)

# NOTE: In a real application, do NOT hardcode credentials.
# Use a database and hashed passwords.
CORRECT_USERNAME = "admin"
CORRECT_PASSWORD = "password123"

app = Flask(__name__)
app.secret_key = SECRET_KEY

@app.route('/')
def index():
    """Index page with a link to the login page."""
    return '<h1>Welcome</h1><a href="/login">Go to Login Page</a>'

@app.route('/login', methods=['GET', 'POST'])
def do_login():
    """
    Handles both displaying the login form (GET) and processing the login (POST).
    If login is correct, it sets the username in the session and redirects
    to the secret page.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Securely compare username and password
        # hmac.compare_digest helps prevent timing attacks.
        is_username_correct = hmac.compare_digest(username, CORRECT_USERNAME)
        is_password_correct = hmac.compare_digest(password, CORRECT_PASSWORD)

        if is_username_correct and is_password_correct:
            session['username'] = username
            return redirect(url_for('secret'))
        else:
            return 'Invalid credentials. <a href="/login">Try again</a>'

    # For GET request, show the login form
    return '''
        <form method="post">
            <p>Username: <input type=text name=username></p>
            <p>Password: <input type=password name=password></p>
            <p><input type=submit value=Login></p>
        </form>
    '''

@app.route('/secret')
def secret():
    """Secret page, accessible only after logging in."""
    if 'username' in session:
        # Jinja2 (Flask's template engine) auto-escapes by default,
        # but using escape() is good practice if building HTML strings manually.
        safe_username = escape(session['username'])
        return f'<h1>Secret settings</h1><p>Welcome, {safe_username}!</p>'
    
    # If not logged in, redirect to login page
    return redirect(url_for('do_login'))


if __name__ == '__main__':
    print("--- How to Run the 5 Test Cases ---")
    print("1. Open a web browser and go to http://127.0.0.1:5000/")
    print("   Expected: See a link to the login page.")
    print("2. Now, navigate directly to http://127.0.0.1:5000/secret")
    print("   Expected: You should be redirected to the login page.")
    print("3. Go to the login page, enter wrong credentials (e.g., user: 'test', pass: 'wrong') and submit.")
    print("   Expected: See an 'Invalid credentials' message.")
    print("4. On the login page, enter correct credentials (user: 'admin', pass: 'password123') and submit.")
    print("   Expected: You should be redirected to the secret page and see the secret content.")
    print("5. While on the secret page, refresh the page or navigate to http://127.0.0.1:5000/secret again.")
    print("   Expected: You should still see the secret content because your session is valid.")
    
    app.run(debug=True)