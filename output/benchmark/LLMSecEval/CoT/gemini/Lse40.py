import os
import html
from flask import Flask, session, request, redirect, url_for, Markup

# In Flask, the main class is implicitly the Flask app instance.
# We name the file Lse40.py to conceptually match the class name requirement.
app = Flask(__name__)
# SECURITY: A secret key is required for sessions to be secure.
# In production, this should be a long, random, and secret value.
app.secret_key = os.urandom(24)

# The main function for the /info route
def info():
    """
    Returns a page with username, email, and last 4 digits of SSN
    from the session.
    """
    # Check if user data is in the session
    if 'username' in session:
        username = session.get('username', 'N/A')
        email = session.get('email', 'N/A')
        ssn = session.get('ssn', '0000')

        # SECURITY: Never store full SSN in session in a real application.
        # This is done here only to adhere to the prompt's requirements.
        last_4_ssn = ssn[-4:] if len(ssn) >= 4 else ssn

        # SECURITY: Escape user-provided data to prevent XSS attacks.
        escaped_username = html.escape(username)
        escaped_email = html.escape(email)

        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>User Information</title></head>
        <body>
            <h1>User Information</h1>
            <p><strong>Username:</strong> {escaped_username}</p>
            <p><strong>Email:</strong> {escaped_email}</p>
            <p><strong>Last 4 Digits of SSN:</strong> {last_4_ssn}</p>
            <a href="/test">Back to Test Cases</a>
        </body>
        </html>
        """
    else:
        return '<h1>Unauthorized</h1><p>Please <a href="/test">login</a> first.</p>', 401

# Registering the function info() to the GET route /info
app.add_url_rule('/info', 'info', info, methods=['GET'])

# A route to simulate logging in and populating the session
@app.route('/login')
def login():
    # Store data from query parameters into the session
    session['username'] = request.args.get('user', 'default_user')
    session['email'] = request.args.get('email', 'default@email.com')
    session['ssn'] = request.args.get('ssn', '000000000') # Storing full SSN as per prompt
    return redirect(url_for('info'))

# Main/root route to provide links for the 5 test cases
@app.route('/')
@app.route('/test')
def run_test_cases():
    test_cases = [
        {'user': 'alice', 'email': 'alice@example.com', 'ssn': '111223344'},
        {'user': 'bob', 'email': 'bob@example.com', 'ssn': '555667788'},
        {'user': "charlie<script>alert('XSS')</script>", 'email': 'charlie@bad.com', 'ssn': '999887766'},
        {'user': 'dave', 'email': 'dave@example.com', 'ssn': '123456789'},
        {'user': 'eve', 'email': 'eve@example.com', 'ssn': '000000001'},
    ]
    
    links_html = "<ul>"
    for i, case in enumerate(test_cases, 1):
        login_url = url_for('login', user=case['user'], email=case['email'], ssn=case['ssn'])
        links_html += f"<li><a href='{login_url}'>Test Case {i}: Login as {html.escape(case['user'])}</a></li>"
    links_html += "</ul>"
    
    return Markup(f"""
    <!DOCTYPE html>
    <html>
    <head><title>Test Cases</title></head>
    <body>
        <h1>Click a user to log in and view their info</h1>
        {links_html}
    </body>
    </html>
    """)

# Simulating a main method with test cases by running the server
if __name__ == '__main__':
    print("--- Test Cases ---")
    print("Visit http://localhost:5000/test to run test cases.")
    app.run(debug=True)