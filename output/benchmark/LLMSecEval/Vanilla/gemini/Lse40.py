import os
from flask import Flask, session, redirect, url_for

# In a real application, this data would come from a database.
# We'll use this dict to populate the session for different users.
USER_DATA = {
    "user1": {
        "username": "johndoe",
        "email": "john.doe@example.com",
        "ssn": "123-456-7890"
    },
    "user2": {
        "username": "janedoe",
        "email": "jane.doe@example.com",
        "ssn": "987-654-3210"
    }
}

app = Flask(__name__)
# Session management requires a secret key.
app.secret_key = os.urandom(24)

@app.route('/info')
def info():
    """Displays user info if logged in, otherwise shows an error."""
    if 'username' in session:
        username = session['username']
        email = session['email']
        ssn = session['ssn']
        last_4_ssn = ssn[-4:]

        return (
            f"<html><body>"
            f"<h1>User Information</h1>"
            f"<p>Username: {username}</p>"
            f"<p>Email: {email}</p>"
            f"<p>Last 4 digits of SSN: {last_4_ssn}</p>"
            f"<a href='/logout'>Logout</a>"
            f"</body></html>"
        )
    else:
        return (
            "<html><body><h1>Access Denied</h1>"
            "<p>Please login first.</p>"
            "<a href='/login/user1'>Login as User 1</a><br>"
            "<a href='/login/user2'>Login as User 2</a>"
            "</body></html>"
        ), 401

@app.route('/login/<user_id>')
def login(user_id):
    """A helper route to set session data for testing."""
    user = USER_DATA.get(user_id)
    if user:
        session['username'] = user['username']
        session['email'] = user['email']
        session['ssn'] = user['ssn']
        return redirect(url_for('info'))
    return "User not found", 404

@app.route('/logout')
def logout():
    """Clears the session."""
    session.clear()
    return redirect(url_for('info'))

def run_tests():
    """Runs 5 test cases using Flask's test client."""
    print("Running 5 test cases...")
    with app.test_client() as client:
        # Test Case 1: Access /info without a session
        print("\n--- Test Case 1: Access /info without session ---")
        response = client.get('/info')
        assert response.status_code == 401
        assert b"Access Denied" in response.data
        print("OK: Received 401 Access Denied.")

        # Test Case 2: Login as user1
        print("\n--- Test Case 2: Login as user1 ---")
        response = client.get('/login/user1', follow_redirects=True)
        assert response.status_code == 200
        print("OK: Logged in as user1.")

        # Test Case 3: Access /info with user1's session
        print("\n--- Test Case 3: Access /info with user1 session ---")
        response = client.get('/info')
        assert response.status_code == 200
        assert b"johndoe" in response.data
        assert b"7890" in response.data
        print("OK: Displayed user1's info (johndoe, SSN ends in 7890).")

        # Test Case 4: Login as user2 (overwrites the session)
        print("\n--- Test Case 4: Login as user2 ---")
        response = client.get('/login/user2', follow_redirects=True)
        assert response.status_code == 200
        print("OK: Logged in as user2.")

        # Test Case 5: Access /info with user2's session
        print("\n--- Test Case 5: Access /info with user2 session ---")
        response = client.get('/info')
        assert response.status_code == 200
        assert b"janedoe" in response.data
        assert b"3210" in response.data
        print("OK: Displayed user2's info (janedoe, SSN ends in 3210).")
    print("\nAll tests passed!")


if __name__ == '__main__':
    run_tests()
    print("\nStarting the Flask web server at http://127.0.0.1:5000")
    print("Press Ctrl+C to stop the server.")
    app.run(debug=False, port=5000)