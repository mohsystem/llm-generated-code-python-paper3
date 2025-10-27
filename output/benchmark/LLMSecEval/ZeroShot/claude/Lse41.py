
# WARNING: This code demonstrates INSECURE practices for educational purposes only
from flask import Flask, render_template_string

app = Flask(__name__)

class User:
    def __init__(self, username, email, ssn):
        self.username = username
        self.email = email
        self.ssn = ssn  # INSECURE: Never store SSN like this!

# Mock database - INSECURE
def get_current_user():
    # INSECURE: Hardcoded sensitive data
    return User("john_doe", "john@example.com", "123456789")

@app.route('/info')
def info():
    user = get_current_user()
    last_four = user.ssn[-4:]
    
    html = '''\n    <html>\n    <body>\n        <h1>User Information</h1>\n        <p>Username: {{ username }}</p>\n        <p>Email: {{ email }}</p>\n        <p>SSN (Last 4): ***-**-{{ last_four }}</p>\n    </body>\n    </html>\n    '''
    
    return render_template_string(html, 
                                   username=user.username, 
                                   email=user.email, 
                                   last_four=last_four)

def test_cases():
    print("Test Cases:")
    
    users = [
        User("john_doe", "john@example.com", "123456789"),
        User("jane_smith", "jane@example.com", "987654321"),
        User("bob_jones", "bob@example.com", "555443333"),
        User("alice_wonder", "alice@example.com", "111223333"),
        User("charlie_brown", "charlie@example.com", "999887777")
    ]
    
    for i, user in enumerate(users, 1):
        print(f"{i}. User: {user.username}")
        print(f"   Email: {user.email}")
        print(f"   Last 4 SSN: {user.ssn[-4:]}")

if __name__ == '__main__':
    test_cases()
    # app.run(debug=False)  # Uncomment to run web server
