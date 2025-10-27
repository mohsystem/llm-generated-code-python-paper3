
from flask import Flask, session, render_template_string

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

@app.route('/info', methods=['GET'])
def info():
    username = session.get('username', 'N/A')
    email = session.get('email', 'N/A')
    ssn = session.get('ssn', '')
    
    last4_ssn = ''
    if ssn and len(ssn) >= 4:
        last4_ssn = ssn[-4:]
    else:
        last4_ssn = 'N/A'
    
    html_template = '''\n    <html>\n        <body>\n            <h1>User Information</h1>\n            <p>Username: {{ username }}</p>\n            <p>Email: {{ email }}</p>\n            <p>Last 4 digits of SSN: {{ last4_ssn }}</p>\n        </body>\n    </html>\n    '''
    
    return render_template_string(html_template, 
                                 username=username, 
                                 email=email, 
                                 last4_ssn=last4_ssn)

if __name__ == '__main__':
    # Test cases
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['username'] = 'john_doe'
            sess['email'] = 'john@example.com'
            sess['ssn'] = '123456789'
        
        print("Test Case 1:")
        response = client.get('/info')
        print(response.data.decode())
        
        with client.session_transaction() as sess:
            sess['username'] = 'jane_smith'
            sess['email'] = 'jane@example.com'
            sess['ssn'] = '987654321'
        
        print("\\nTest Case 2:")
        response = client.get('/info')
        print(response.data.decode())
        
        with client.session_transaction() as sess:
            sess['username'] = 'bob_wilson'
            sess['email'] = 'bob@example.com'
            sess['ssn'] = '555443333'
        
        print("\\nTest Case 3:")
        response = client.get('/info')
        print(response.data.decode())
        
        with client.session_transaction() as sess:
            sess.clear()
        
        print("\\nTest Case 4 (No session data):")
        response = client.get('/info')
        print(response.data.decode())
        
        with client.session_transaction() as sess:
            sess['username'] = 'alice'
            sess['email'] = 'alice@test.com'
            sess['ssn'] = '12'
        
        print("\\nTest Case 5 (Short SSN):")
        response = client.get('/info')
        print(response.data.decode())
