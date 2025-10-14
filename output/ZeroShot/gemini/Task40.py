import os
import secrets
from flask import Flask, request, session, render_template_string, abort

# In a real app, use a more persistent secret key and load it from a config file.
# This would be the main class if we were using a class-based structure.
# For Flask, the app object is the central point.
# We'll call the file Task40.py to conceptually match the name.
app = Flask("Task40")
app.config['SECRET_KEY'] = os.urandom(24)

# In-memory user data store. In a real app, use a database.
user_data = {"user1": "user1@example.com"}

@app.before_request
def setup_session():
    # Simulate a logged-in user for demonstration purposes.
    # In a real app, this would be handled by a login system.
    if 'username' not in session:
        session['username'] = 'user1'

def get_settings_form(csrf_token):
    """Generates the HTML form, accepting a CSRF token."""
    username = session.get('username')
    current_email = user_data.get(username, "")
    return render_template_string("""
    <html>
    <body>
        <h2>Update Settings for {{ username }}</h2>
        <form action="/settings" method="post">
            <label for="email">Email:</label><br>
            <input type="email" id="email" name="email" value="{{ current_email }}"><br><br>
            <!-- CSRF Protection: Include token in a hidden field -->
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="submit" value="Update">
        </form>
    </body>
    </html>
    """, username=username, current_email=current_email, csrf_token=csrf_token)
    
def get_success_page(username, new_email):
    """Generates the success page HTML."""
    return render_template_string("""
    <html>
    <body>
        <h2>Success!</h2>
        <p>Email for {{ username }} updated to {{ new_email }}.</p>
        <a href="/settings">Go back</a>
    </body>
    </html>
    """, username=username, new_email=new_email)

@app.route('/settings', methods=['GET', 'POST'])
def update_settings():
    if request.method == 'POST':
        # CSRF Protection: Validate token
        submitted_token = request.form.get('csrf_token')
        expected_token = session.pop('csrf_token', None) # Pop to ensure one-time use
        
        if not expected_token or not secrets.compare_digest(expected_token, submitted_token):
            abort(403, "Forbidden: Invalid CSRF Token")
        
        # Process the form data
        username = session.get('username')
        new_email = request.form.get('email')
        if not new_email or not username:
             abort(400, "Bad Request: Email is required.")
        
        user_data[username] = new_email
        return get_success_page(username, new_email)
    
    # For GET request
    # CSRF Protection: Generate and store token in session
    csrf_token = secrets.token_hex(16)
    session['csrf_token'] = csrf_token
    return get_settings_form(csrf_token)


def main():
    """Main function to run the app and print test instructions."""
    port = 5000
    print(f"Server starting on http://localhost:{port}")
    print("--- How to Test ---")
    print("Use a tool like curl. A 'cookie-jar.txt' file will be created to manage the session.")
    print("\n--- Test Case 1: Load the form (GET request) ---")
    print(f"curl -v -c cookie-jar.txt http://localhost:{port}/settings")
    print("=> This will create a session and return a form with a CSRF token.")
    
    print("\n--- Test Case 2: Submit form with a valid token (SUCCESS) ---")
    print("1. First, run Test Case 1 to get a valid token from the HTML output.")
    print("2. Replace 'VALID_TOKEN_FROM_STEP_1' with the actual token.")
    print(f"curl -v -X POST -b cookie-jar.txt -c cookie-jar.txt \\")
    print(f"  --data-urlencode \"email=new.email@example.com\" \\")
    print(f"  --data-urlencode \"csrf_token=VALID_TOKEN_FROM_STEP_1\" \\")
    print(f"  http://localhost:{port}/settings")
    
    print("\n--- Test Case 3: Submit form with an invalid token (FAIL) ---")
    print(f"curl -v -X POST -b cookie-jar.txt -c cookie-jar.txt \\")
    print(f"  --data-urlencode \"email=another.email@example.com\" \\")
    print(f"  --data-urlencode \"csrf_token=invalid_token_12345\" \\")
    print(f"  http://localhost:{port}/settings")

    print("\n--- Test Case 4: Submit form with a missing token (FAIL) ---")
    print(f"curl -v -X POST -b cookie-jar.txt -c cookie-jar.txt \\")
    print(f"  --data-urlencode \"email=another.email@example.com\" \\")
    print(f"  http://localhost:{port}/settings")

    print("\n--- Test Case 5: Submit form with a valid token but no session cookie (FAIL) ---")
    print("1. First, run Test Case 1 to get a valid token.")
    print("2. Replace 'VALID_TOKEN_FROM_STEP_1' with the actual token.")
    print("3. Note we are NOT sending the cookie jar (-b flag).")
    print(f"curl -v -X POST \\")
    print(f"  --data-urlencode \"email=another.email@example.com\" \\")
    print(f"  --data-urlencode \"csrf_token=VALID_TOKEN_FROM_STEP_1\" \\")
    print(f"  http://localhost:{port}/settings")

    app.run(port=port, debug=False)

if __name__ == '__main__':
    main()