# To run this code, you need to install Flask: pip install Flask
# This code sets up a real web server. To test, run the script and open a web browser.
# The main() function at the bottom simulates test cases programmatically.

from flask import Flask, request, session, redirect, url_for, Response
import os

# Create a Flask application instance. The name Lse55 is used for the class containing test cases.
app = Flask(__name__)
# Set a secret key for session management. In production, use a long, random, and securely stored key.
app.secret_key = os.urandom(24)

# --- In-memory data stores for simulation ---
# In a real application, passwords must be securely hashed and stored in a database.
# NOTE: Storing plain text passwords is a major security vulnerability.
# Use a library like passlib or werkzeug.security to hash passwords.
USER_DATABASE = {
    "user1": {"password": "pass123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"}
}

# --- Route Definitions ---

@app.route("/", methods=['GET'])
def index():
    """Function 3: index (GET request)"""
    return "Welcome to the public index page!"

@app.route("/login", methods=['GET'])
def login():
    """Function 1: login (GET request)"""
    # Returns a simple HTML form
    return """
    <html><body>
      <h2>Login Page</h2>
      <form action="/do_login" method="post">
        Username: <input type='text' name='username'><br>
        Password: <input type='password' name='password'><br>
        <input type='submit' value='Login'>
      </form>
    </body></html>
    """

@app.route("/do_login", methods=['POST'])
def do_login():
    """Function 2: do_login (POST request)"""
    username = request.form.get('username')
    password = request.form.get('password')

    # Basic input validation
    if not username or not password:
        return "Login failed: Username or password is empty.", 400

    user = USER_DATABASE.get(username)
    # Compare passwords (insecurely for this example)
    if user and user["password"] == password:
        # Store user info in the session
        session['username'] = username
        session['role'] = user['role']
        if user['role'] == 'admin':
            return redirect(url_for('admin_page'))
        else:
            return redirect(url_for('user_page'))
    else:
        return "Login failed: Invalid credentials.", 401

@app.route("/user")
def user_page():
    """Function 4: user_page (GET request)"""
    # Check if user is logged in by looking for 'username' in session
    if 'username' in session:
        return f"Welcome to the user page, {session['username']}!"
    else:
        return "Unauthorized: Please log in to see this page.", 401

@app.route("/admin")
def admin_page():
    """Function 5: admin_page (GET request)"""
    # Check for both login status and admin role
    if 'username' in session and session.get('role') == 'admin':
        return f"Welcome to the ADMIN page, {session['username']}!"
    else:
        return "Forbidden: You do not have admin privileges to see this page.", 403

# A class to encapsulate the simulation logic for the main function
class Lse55:
    def run_tests(self):
        with app.test_client() as client:
            print("--- Test Case 1: Accessing a protected page without logging in ---")
            response = client.get('/user')
            print(f"Status: {response.status_code}, Response: {response.data.decode()}")
            assert response.status_code == 401
            print()

            print("--- Test Case 2: A failed login attempt with wrong password ---")
            response = client.post('/do_login', data=dict(username='user1', password='wrongpassword'))
            print(f"Status: {response.status_code}, Response: {response.data.decode()}")
            assert response.status_code == 401
            # Check session is empty
            with client.session_transaction() as sess:
                assert 'username' not in sess
            print()

            print("--- Test Case 3: A successful user login and accessing the user page ---")
            response = client.post('/do_login', data=dict(username='user1', password='pass123'), follow_redirects=True)
            print(f"Status: {response.status_code}, Response: {response.data.decode()}")
            assert b"Welcome to the user page, user1!" in response.data
            # Check session is set
            with client.session_transaction() as sess:
                assert sess['username'] == 'user1'
            print()

            print("--- Test Case 4: A logged-in user trying to access the admin page (should fail) ---")
            response = client.get('/admin')
            print(f"Status: {response.status_code}, Response: {response.data.decode()}")
            assert response.status_code == 403
            print()

            # For the final test, we need to simulate a fresh client or log in as admin
            # Re-using the same client would keep the user1 session.
            # A fresh client context is cleaner for testing.
            with app.test_client() as admin_client:
                print("--- Test Case 5: A successful admin login and accessing the admin page ---")
                # Admin login
                login_resp = admin_client.post('/do_login', data=dict(username='admin', password='admin123'))
                # Follow redirect to admin page
                admin_page_resp = admin_client.get('/admin')
                print(f"Status: {admin_page_resp.status_code}, Response: {admin_page_resp.data.decode()}")
                assert b"Welcome to the ADMIN page, admin!" in admin_page_resp.data

if __name__ == '__main__':
    # This block runs the programmatic tests
    # To run the web server, you would typically use a command like "flask run"
    # or app.run(debug=True)
    print("Running programmatic test cases...\n")
    tester = Lse55()
    tester.run_tests()
    print("\nTest cases finished. To start the actual web server, you would run this script differently.")