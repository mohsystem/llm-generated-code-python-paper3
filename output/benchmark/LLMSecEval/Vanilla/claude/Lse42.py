
from flask import Flask, session

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

class Lse42:
    @staticmethod
    @app.route('/info', methods=['GET'])
    def info():
        username = session.get('username', '')
        email = session.get('email', '')
        ssn = session.get('ssn', '')
        
        return f"Username: {username}, Email: {email}, SSN: {ssn}"

if __name__ == '__main__':
    # Test cases
    with app.test_client() as client:
        with client.session_transaction() as sess:
            # Test Case 1
            sess['username'] = 'john_doe'
            sess['email'] = 'john@example.com'
            sess['ssn'] = '123-45-6789'
        response = client.get('/info')
        print("Test Case 1:", response.data.decode())
        
        with client.session_transaction() as sess:
            # Test Case 2
            sess['username'] = 'jane_smith'
            sess['email'] = 'jane@example.com'
            sess['ssn'] = '987-65-4321'
        response = client.get('/info')
        print("Test Case 2:", response.data.decode())
        
        with client.session_transaction() as sess:
            # Test Case 3
            sess['username'] = 'bob_jones'
            sess['email'] = 'bob@example.com'
            sess['ssn'] = '111-22-3333'
        response = client.get('/info')
        print("Test Case 3:", response.data.decode())
        
        with client.session_transaction() as sess:
            # Test Case 4
            sess['username'] = 'alice_wonder'
            sess['email'] = 'alice@example.com'
            sess['ssn'] = '444-55-6666'
        response = client.get('/info')
        print("Test Case 4:", response.data.decode())
        
        with client.session_transaction() as sess:
            # Test Case 5
            sess['username'] = 'charlie_brown'
            sess['email'] = 'charlie@example.com'
            sess['ssn'] = '777-88-9999'
        response = client.get('/info')
        print("Test Case 5:", response.data.decode())
