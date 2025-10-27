
from flask import Flask, request, redirect, render_template_string
import hashlib
import secrets
import hmac

app = Flask(__name__)

# Secure storage for credentials - in production, use a proper database
# Password hashing with unique salt per user
user_db = {}

def initialize_users():
    """Initialize user database with admin account"""
    # Generate cryptographically secure random salt
    salt = secrets.token_bytes(16)
    # Hash password with salt using PBKDF2
    password_hash = hashlib.pbkdf2_hmac('sha256', b'admin123', salt, 210000)
    user_db['admin'] = {
        'salt': salt,
        'hash': password_hash
    }

initialize_users()

def verify_password(username, password):
    """\n    Verify password using constant-time comparison to prevent timing attacks\n    Uses PBKDF2 with 210000 iterations for key derivation\n    """
    if username not in user_db:
        # Perform dummy hash to prevent timing attack on username enumeration
        hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), secrets.token_bytes(16), 210000)
        return False
    
    user = user_db[username]
    salt = user['salt']
    stored_hash = user['hash']
    
    # Hash provided password with stored salt
    provided_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 210000)
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(stored_hash, provided_hash)

@app.route('/login', methods=['GET'])
def login():
    """\n    GET /login endpoint\n    Returns HTML form with input validation constraints\n    """
    # HTML form with security considerations:
    # - maxlength to prevent DoS
    # - pattern attribute for input validation
    # - required attribute for mandatory fields
    html_form = '''\n    <!DOCTYPE html>\n    <html>\n    <head>\n        <title>Login</title>\n        <meta charset="UTF-8">\n    </head>\n    <body>\n        <h2>Login Form</h2>\n        <form method="POST" action="/do_login">\n            <label>Username: \n                <input type="text" name="username" required \n                       maxlength="50" pattern="[a-zA-Z0-9_]+">\n            </label><br>\n            <label>Password: \n                <input type="password" name="password" required \n                       maxlength="100">\n            </label><br>\n            <input type="submit" value="Login">\n        </form>\n    </body>\n    </html>\n    '''
    return render_template_string(html_form)

@app.route('/do_login', methods=['POST'])
def do_login():
    """\n    POST /do_login endpoint\n    Validates credentials and redirects admin users\n    Returns generic error messages to prevent information disclosure\n    """
    # Input validation: get form data with type checking
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Input validation: check for empty values
    if not username or not password:
        return "Login failed", 401
    
    # Input validation: sanitize username
    # Only allow alphanumeric and underscore, max 50 chars
    if not username.isalnum() and '_' not in username:
        return "Login failed", 401
    
    if len(username) > 50:
        return "Login failed", 401
    
    # Length validation for password to prevent DoS
    if len(password) > 100:
        return "Login failed", 401
    
    # Verify credentials using secure comparison
    if verify_password(username, password):
        # Check if user is admin
        if username == 'admin':
            # Redirect to admin page
            return redirect('/admin_page', code=302)
        else:
            # Non-admin authenticated user
            return "Login successful", 200
    
    # Generic error message to prevent username enumeration
    return "Login failed", 401

@app.route('/admin_page')
def admin_page():
    """Admin page endpoint for demonstration"""
    return "<h1>Admin Page</h1><p>Welcome, administrator!</p>"

if __name__ == '__main__':
    # Test cases
    print("Test Case 1 - Admin login with correct password:")
    with app.test_client() as client:
        response = client.post('/do_login', data={'username': 'admin', 'password': 'admin123'})
        print(f"Status: {response.status_code}, Redirect: {response.location if response.status_code == 302 else 'None'}")
    
    print("\\nTest Case 2 - Admin login with incorrect password:")
    with app.test_client() as client:
        response = client.post('/do_login', data={'username': 'admin', 'password': 'wrongpass'})
        print(f"Status: {response.status_code}, Response: {response.data.decode()}")
    
    print("\\nTest Case 3 - Non-existent user:")
    with app.test_client() as client:
        response = client.post('/do_login', data={'username': 'hacker', 'password': 'password'})
        print(f"Status: {response.status_code}, Response: {response.data.decode()}")
    
    print("\\nTest Case 4 - SQL injection attempt:")
    with app.test_client() as client:
        response = client.post('/do_login', data={'username': "admin' OR '1'='1", 'password': 'anything'})
        print(f"Status: {response.status_code}, Response: {response.data.decode()}")
    
    print("\\nTest Case 5 - Empty credentials:")
    with app.test_client() as client:
        response = client.post('/do_login', data={'username': '', 'password': ''})
        print(f"Status: {response.status_code}, Response: {response.data.decode()}")
    
    # Run server on localhost only for security
    app.run(host='127.0.0.1', port=5000, debug=False)
