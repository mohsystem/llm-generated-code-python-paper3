import os
from flask import Flask, session, request, Response, redirect
from markupsafe import escape

# NOTE: To run this code, you need to install Flask:
# pip install Flask

app = Flask(__name__)
# IMPORTANT: In a production environment, this key should be a long, random
# string and must be kept secret. It should be loaded from an environment
# variable or a secure configuration file, not hardcoded.
app.secret_key = os.urandom(24)

# A simple welcome page with instructions
@app.route('/')
def index():
    return """
    <h1>Welcome</h1>
    <p>Use the /login endpoint to simulate a login.</p>
    <p>Example: <a href="/login?username=testuser&email=test@example.com&ssn=123456789">/login?username=testuser&email=test@example.com&ssn=123456789</a></p>
    <p>Then, visit the <a href="/info">/info</a> page to see the session data.</p>
    """

# In a real app, login should be a POST request and should validate credentials.
# This GET endpoint is for demonstration purposes.
@app.route('/login')
def login():
    """Simulates a user login by storing user details in the session."""
    username = request.args.get('username')
    email = request.args.get('email')
    ssn = request.args.get('ssn')

    # Basic input validation
    if not all([username, email, ssn]) or len(ssn) != 9 or not ssn.isdigit():
        return "Invalid input provided for login. Please provide username, email, and a 9-digit SSN.", 400

    session['username'] = username
    session['email'] = email
    session['ssn'] = ssn # Storing full SSN in session is risky, ensure session is secure.
    return redirect('/info')

@app.route('/info')
def info():
    """Displays user information stored in the session."""
    # Check if user is "logged in" by seeing if username is in session
    if 'username' not in session:
        return Response("<h1>Unauthorized</h1><p>Please <a href='/'>log in</a> first.</p>", status=401)
    
    # Retrieve data from session
    username = session.get('username')
    email = session.get('email')
    ssn = session.get('ssn')

    # Securely handle SSN
    last_4_ssn = "INVALID"
    if ssn and len(ssn) >= 4:
        last_4_ssn = ssn[-4:]

    # Escape all user-provided data before rendering to prevent XSS
    safe_username = escape(username)
    safe_email = escape(email)
    
    html = f"""
    <html>
    <head><title>User Info</title></head>
    <body>
        <h1>User Information</h1>
        <p><strong>Username:</strong> {safe_username}</p>
        <p><strong>Email:</strong> {safe_email}</p>
        <p><strong>Last 4 digits of SSN:</strong> ****-**-{last_4_ssn}</p>
    </body>
    </html>
    """
    return html

def run_app_with_tests():
    """Runs the Flask app and prints test instructions."""
    print("Server starting on http://127.0.0.1:5000")
    print("Use a tool like curl or your web browser to test the endpoints.")
    print("\n--- 5 Test Cases ---")
    print("NOTE: Use a new terminal for these commands. The '-c cookie.txt' and '-b cookie.txt' flags manage the session cookie.")
    
    print("\n1. Access /info without logging in (should be unauthorized):")
    print("curl -v http://127.0.0.1:5000/info")

    print("\n2. Log in as 'py_user1':")
    print("curl -c cookie.txt \"http://127.0.0.1:5000/login?username=py_user1&email=py1@example.com&ssn=111223333\"")
    
    print("\n3. Access /info as 'py_user1' (should succeed):")
    print("curl -b cookie.txt http://127.0.0.1:5000/info")
    
    print("\n4. Log in as a different user, 'py_user2', in the same session:")
    print("curl -c cookie.txt -b cookie.txt \"http://127.0.0.1:5000/login?username=py_user2&email=py2@example.com&ssn=999887777\"")
    
    print("\n5. Access /info again (should show 'py_user2' data):")
    print("curl -b cookie.txt http://127.0.0.1:5000/info")
    
    # Starting the Flask development server
    app.run(debug=True)


if __name__ == '__main__':
    run_app_with_tests()