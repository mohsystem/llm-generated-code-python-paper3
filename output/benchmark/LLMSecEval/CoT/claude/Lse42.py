
from flask import Flask, session, jsonify
from functools import wraps
import secrets
import html

app = Lse42 = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

def mask_ssn(ssn):
    if not ssn or len(ssn) < 4:
        return "***-**-****"
    return f"***-**-{ssn[-4:]}"

def require_session(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return "Unauthorized: No session found", 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/info', methods=['GET'])
@require_session
def info():
    username = html.escape(session.get('username', 'N/A'))
    email = html.escape(session.get('email', 'N/A'))
    ssn = session.get('ssn', 'N/A')
    
    return f"Username: {username}; Email: {email}; SSN: {mask_ssn(ssn)}"

if __name__ == '__main__':
    # Test cases
    with app.test_client() as client:
        # Test case 1: Valid session
        with client.session_transaction() as sess:
            sess['username'] = 'john_doe'
            sess['email'] = 'john@example.com'
            sess['ssn'] = '123-45-6789'
        response = client.get('/info')
        print(f"Test Case 1: {response.data.decode()}")
        
        # Test case 2: Another valid session
        with client.session_transaction() as sess:
            sess['username'] = 'jane_smith'
            sess['email'] = 'jane@example.com'
            sess['ssn'] = '987-65-4321'
        response = client.get('/info')
        print(f"Test Case 2: {response.data.decode()}")
        
        # Test case 3: No session
        with client.session_transaction() as sess:
            sess.clear()
        response = client.get('/info')
        print(f"Test Case 3: {response.data.decode()}")
        
        # Test case 4: XSS attempt
        with client.session_transaction() as sess:
            sess['username'] = '<script>alert("XSS")</script>'
            sess['email'] = 'test@example.com'
            sess['ssn'] = '111-11-1111'
        response = client.get('/info')
        print(f"Test Case 4: {response.data.decode()}")
        
        # Test case 5: Incomplete data
        with client.session_transaction() as sess:
            sess['username'] = 'test_user'
            sess.pop('email', None)
            sess.pop('ssn', None)
        response = client.get('/info')
        print(f"Test Case 5: {response.data.decode()}")
