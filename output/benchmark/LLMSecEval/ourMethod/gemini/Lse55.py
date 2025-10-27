import threading
import time
import requests
from flask import Flask, request, Response

app = Flask(__name__)

# GET /login
@app.route('/login', methods=['GET'])
def login():
    """Serves the login page."""
    html_form = """
    <h1>Login Page</h1>
    <form action="/do_login" method="post">
      Username: <input type="text" name="username"><br>
      Password: <input type="password" name="password"><br>
      <input type="submit" value="Login">
    </form>
    """
    return Response(html_form, mimetype='text/html')

# POST /do_login
@app.route('/do_login', methods=['POST'])
def do_login():
    """Handles the login form submission."""
    # Rules#6: Ensure all input is validated and sanitized
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return Response("<h1>Username and password cannot be empty.</h1>", status=400, mimetype='text/html')

    # In a real application, you would validate credentials against a database.
    # Rules#1, #3, #4, #5: NEVER store passwords in plaintext.
    # Use a strong, salted hashing algorithm like Argon2 from a library like 'passlib'.
    # The following is for demonstration purposes ONLY and is highly insecure.
    if username == "admin" and password == "password123":
        return Response("<h1>Admin Login Successful!</h1>", mimetype='text/html')
    elif username == "user" and password == "password123":
        return Response("<h1>User Login Successful!</h1>", mimetype='text/html')
    else:
        return Response("<h1>Login Failed: Invalid credentials.</h1>", status=401, mimetype='text/html')

# GET /
@app.route('/', methods=['GET'])
def index():
    """Serves the index page."""
    return Response("<h1>Welcome to the Index Page!</h1>", mimetype='text/html')

# GET /user
@app.route('/user', methods=['GET'])
def user_page():
    """Serves the user page."""
    return Response("<h1>Welcome to the User Page!</h1>", mimetype='text/html')

# GET /admin
@app.route('/admin', methods=['GET'])
def admin_page():
    """Serves the admin page."""
    return Response("<h1>Welcome to the Admin Page!</h1>", mimetype='text/html')

def run_tests():
    """Runs test cases against the server."""
    base_url = "http://127.0.0.1:5000"
    tests = [
        {"name": "index function", "method": "GET", "url": f"{base_url}/", "data": None},
        {"name": "login function", "method": "GET", "url": f"{base_url}/login", "data": None},
        {"name": "do_login function", "method": "POST", "url": f"{base_url}/do_login", "data": {"username": "admin", "password": "password123"}},
        {"name": "user_page function", "method": "GET", "url": f"{base_url}/user", "data": None},
        {"name": "admin_page function", "method": "GET", "url": f"{base_url}/admin", "data": None},
    ]

    print("\n--- Running 5 Test Cases ---")
    for i, test in enumerate(tests):
        try:
            print(f"Test Case {i+1}: {test['name']} ({test['method']} {test['url']})")
            if test['method'] == 'GET':
                response = requests.get(test['url'], timeout=5)
            else: # POST
                response = requests.post(test['url'], data=test['data'], timeout=5)
            
            print(f"Status Code: {response.status_code}")
            # Truncate long responses for cleaner output
            body = response.text.replace('\n', ' ')
            print(f"Response Body: {body[:100]}...")
        except requests.exceptions.RequestException as e:
            print(f"Error during test: {e}")
        finally:
            print("----------------------------")

if __name__ == '__main__':
    # Running the server in a separate thread to allow tests to run
    server_thread = threading.Thread(target=lambda: app.run(host='127.0.0.1', port=5000, debug=False))
    server_thread.daemon = True
    server_thread.start()
    time.sleep(1) # Give the server a moment to start

    run_tests()
    
    # The script will exit here, terminating the daemon thread.
    print("Tests finished. Server is shutting down.")