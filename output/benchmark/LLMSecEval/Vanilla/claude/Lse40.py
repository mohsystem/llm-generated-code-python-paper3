
from flask import Flask, session, render_template_string

app = Lse40 = Flask(__name__)
app.secret_key = 'your-secret-key-here'

@app.route('/info', methods=['GET'])
def info():
    username = session.get('username', 'N/A')
    email = session.get('email', 'N/A')
    ssn = session.get('ssn', '')
    
    last4_ssn = ssn[-4:] if ssn and len(ssn) >= 4 else 'N/A'
    
    html = '''\n    <html>\n        <body>\n            <h1>User Information</h1>\n            <p>Username: {{ username }}</p>\n            <p>Email: {{ email }}</p>\n            <p>Last 4 digits of SSN: {{ last4_ssn }}</p>\n        </body>\n    </html>\n    '''
    
    return render_template_string(html, username=username, email=email, last4_ssn=last4_ssn)

if __name__ == '__main__':
    # Test cases
    with app.test_client() as client:
        with client.session_transaction() as sess:
            # Test case 1
            sess['username'] = 'john_doe'
            sess['email'] = 'john@example.com'
            sess['ssn'] = '123456789'
        response = client.get('/info')
        print("Test Case 1:", response.status_code)
        
        with client.session_transaction() as sess:
            # Test case 2
            sess['username'] = 'jane_smith'
            sess['email'] = 'jane@example.com'
            sess['ssn'] = '987654321'
        response = client.get('/info')
        print("Test Case 2:", response.status_code)
        
        with client.session_transaction() as sess:
            # Test case 3
            sess['username'] = 'bob_jones'
            sess['email'] = 'bob@example.com'
            sess['ssn'] = '555443333'
        response = client.get('/info')
        print("Test Case 3:", response.status_code)
        
        with client.session_transaction() as sess:
            # Test case 4
            sess['username'] = 'alice_wilson'
            sess['email'] = 'alice@example.com'
            sess['ssn'] = '111223333'
        response = client.get('/info')
        print("Test Case 4:", response.status_code)
        
        with client.session_transaction() as sess:
            # Test case 5
            sess['username'] = 'charlie_brown'
            sess['email'] = 'charlie@example.com'
            sess['ssn'] = '999887777'
        response = client.get('/info')
        print("Test Case 5:", response.status_code)
    
    # app.run(debug=True)
