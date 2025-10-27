import os
import secrets
from flask import Flask, session, redirect, url_for, escape, request

# It is crucial to set a secret key for session management.
# This key should be a long, random, and secret string.
# For production, use an environment variable.
# Example: export SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
SECRET_KEY = os.environ.get('SECRET_KEY')

# Create the Flask application.
app = Flask(__name__)

if SECRET_KEY:
    app.secret_key = SECRET_KEY
else:
    print("FATAL: SECRET_KEY environment variable is not set.")
    print("Please set a strong secret key for session management.")
    # For demonstration purposes only, we generate a temporary key.
    # In a real application, you should exit if the key is not set.
    app.secret_key = secrets.token_hex(24)
    print("WARNING: Using a temporary secret key. Sessions will not persist across restarts.")


@app.route('/')
def index():
    """A dummy index page that provides a login link."""
    if 'username' in session:
        return 'You are already logged in. <a href="/info">View Info</a> or <a href="/logout">Logout</a>.'
    return 'Welcome! Please <a href="/login">login</a> to set up your session.'

@app.route('/login')
def login():
    """A dummy login route to populate the session."""
    session['username'] = 'testuser'
    session['email'] = 'test@example.com'
    # Storing sensitive data like SSN in a session should be done with care.
    session['ssn'] = '123-456-7890'
    return redirect(url_for('info'))

@app.route('/info')
def info():
    """Displays user info from the session."""
    if 'username' not in session:
        return redirect(url_for('index'))

    username = escape(session.get('username', 'N/A'))
    email = escape(session.get('email', 'N/A'))
    ssn = session.get('ssn', '')
    
    if len(ssn) >= 4:
        last_4_ssn = escape(ssn[-4:])
    else:
        last_4_ssn = escape(ssn)

    return f"""
    <html>
    <head><title>User Info</title></head>
    <body>
        <h1>User Information</h1>
        <p>Username: {username}</p>
        <p>Email: {email}</p>
        <p>SSN (last 4 digits): ****-**-{last_4_ssn}</p>
        <a href="/logout">Logout</a>
    </body>
    </html>
    """
    
@app.route('/logout')
def logout():
    """Clears the session."""
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # The main block includes test cases.
    # To run the server normally, you would use a WSGI server like Gunicorn or Waitress.
    # For development: flask run
    
    print("Running 5 test cases...")
    with app.test_client() as client:
        # Test Case 1: Access /info without a session, should redirect.
        print("\n--- Test Case 1: Access /info without session ---")
        response = client.get('/info')
        assert response.status_code == 302
        assert response.location == '/'
        print("Result: OK (Redirected as expected)")

        # Test Case 2: Access /login to set up session, then access /info.
        print("\n--- Test Case 2: Login and access /info ---")
        response_login = client.get('/login', follow_redirects=True)
        assert response_login.status_code == 200
        assert b'User Information' in response_login.data
        print("Result: OK (Login successful, info page displayed)")

        # Test Case 3: Verify data on the /info page.
        print("\n--- Test Case 3: Verify data on info page ---")
        response_info = client.get('/info')
        assert b'testuser' in response_info.data
        assert b'test@example.com' in response_info.data
        print("Result: OK (Username and email are correct)")
        
        # Test Case 4: Verify SSN is properly masked.
        print("\n--- Test Case 4: Verify SSN masking ---")
        assert b'****-**-7890' in response_info.data
        assert b'123-456-7890' not in response_info.data
        print("Result: OK (SSN is masked correctly)")
        
        # Test Case 5: Logout and then try to access /info.
        print("\n--- Test Case 5: Logout and attempt to access info ---")
        response_logout = client.get('/logout', follow_redirects=True)
        assert b'Welcome!' in response_logout.data
        response_info_after_logout = client.get('/info')
        assert response_info_after_logout.status_code == 302
        print("Result: OK (Logged out, access to /info is redirected)")

    print("\nAll tests passed. To run the server for manual testing, use 'flask run'.")
    # To run the server for manual browsing:
    # app.run(debug=True, port=5000)