
from flask import Flask, session, render_template_string
import html
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

def get_last_four_digits(ssn):
    if not ssn or len(ssn) < 4:
        return "****"
    return ssn[-4:]

@app.route('/info', methods=['GET'])
def info():
    username = session.get('username', '')
    email = session.get('email', '')
    ssn = session.get('ssn', '')
    
    if not username and not email and not ssn:
        return "<html><body><h1>Error: No session data found</h1></body></html>", 400
    
    username_safe = html.escape(username)
    email_safe = html.escape(email)
    ssn_last4 = html.escape(get_last_four_digits(ssn))
    
    template = """\n    <html>\n    <head><title>User Info</title></head>\n    <body>\n        <h1>User Information</h1>\n        <p><strong>Username:</strong> {{ username }}</p>\n        <p><strong>Email:</strong> {{ email }}</p>\n        <p><strong>SSN (Last 4):</strong> {{ ssn_last4 }}</p>\n    </body>\n    </html>\n    """
    
    return render_template_string(template, 
                                 username=username_safe, 
                                 email=email_safe, 
                                 ssn_last4=ssn_last4)

if __name__ == '__main__':
    with app.test_client() as client:
        with client.session_transaction() as sess:
            # Test case 1: Normal data
            sess['username'] = 'john_doe'
            sess['email'] = 'john@example.com'
            sess['ssn'] = '123456789'
        response = client.get('/info')
        print("Test 1:", response.data.decode())
        
        with client.session_transaction() as sess:
            # Test case 2: XSS attempt
            sess['username'] = "jane<script>alert('xss')</script>"
            sess['email'] = 'jane@test.com'
            sess['ssn'] = '987654321'
        response = client.get('/info')
        print("\\nTest 2 (XSS):", response.data.decode())
        
        with client.session_transaction() as sess:
            # Test case 3: Short SSN
            sess['username'] = 'bob'
            sess['email'] = 'bob@mail.com'
            sess['ssn'] = '111'
        response = client.get('/info')
        print("\\nTest 3 (Short SSN):", response.data.decode())
        
        with client.session_transaction() as sess:
            # Test case 4: Normal data
            sess['username'] = 'alice'
            sess['email'] = 'alice@domain.com'
            sess['ssn'] = '555667788'
        response = client.get('/info')
        print("\\nTest 4:", response.data.decode())
        
        with client.session_transaction() as sess:
            # Test case 5: Empty session
            sess.clear()
        response = client.get('/info')
        print("\\nTest 5 (Empty):", response.data.decode())
    
    # Uncomment to run the server
    # app.run(debug=False, port=8080)
