import secrets
from flask import Flask, request, session, render_template_string, abort

# The main class name is emulated by the Flask app name
Task40 = Flask(__name__)
# A secret key is required for session management
Task40.config['SECRET_KEY'] = secrets.token_hex(32)

# HTML template for the settings form.
# The {{ csrf_token }} will be replaced by the actual token.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>User Settings</title>
</head>
<body>
    <h2>Update User Settings</h2>
    {% if message %}
        <p style="color: red;">{{ message }}</p>
    {% endif %}
    <form method="POST" action="/settings">
        Email: <input type="email" name="email"><br/><br/>
        
        <!-- 3. Embed the CSRF token in a hidden form field -->
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        
        <input type="submit" value="Update Settings">
    </form>
    <hr>
    <h3>Test Cases</h3>
    <ol>
        <li><b>Normal Load:</b> Just load this page.</li>
        <li><b>Valid Submission:</b> Fill in the email and submit.</li>
        <li><b>Invalid Token:</b> Use browser dev tools to change the hidden token's value before submitting.</li>
        <li><b>Missing Token:</b> Use browser dev tools to delete the hidden token input before submitting.</li>
        <li><b>Token Replay:</b> Submit successfully, press "Back", and try submitting again.</li>
    </ol>
</body>
</html>
"""

SUCCESS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
</head>
<body>
    <h2>Settings updated successfully!</h2>
    <p>New Email (simulated): {{ email }}</p>
    <a href="/settings">Go back to settings</a>
</body>
</html>
"""

@Task40.route("/")
def index():
    return '<a href="/settings">Go to User Settings</a>'

@Task40.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        # 4. On POST, retrieve tokens from session and form
        session_token = session.pop('csrf_token', None)
        form_token = request.form.get('csrf_token')

        # 5. Validate the token
        if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
            abort(403, "CSRF token invalid")

        # --- CSRF check passed, process the form ---
        email = request.form.get("email")
        # In a real app, you would save the email to a database
        print(f"User settings updated. New email: {email}")
        return render_template_string(SUCCESS_TEMPLATE, email=email)
    
    # For GET requests:
    # 1. Generate a new CSRF token
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    
    # 2. Render the form, passing the token to the template
    return render_template_string(HTML_TEMPLATE, csrf_token=session['csrf_token'])

# No explicit main class is needed in Python Flask, but we simulate it with the app runner.
# This serves as the main entry point with "test cases" described in the comments.
if __name__ == '__main__':
    """
    How to run this code:
    1. Install Flask: pip install Flask
    2. Save the code as a Python file (e.g., task40.py).
    3. Run from the terminal: python task40.py
    4. Open your web browser and go to http://127.0.0.1:5000

    How to perform 5 manual test cases:
    Follow the instructions on the web page that loads at http://127.0.0.1:5000/settings
    1. [Normal Load]: Navigate to http://127.0.0.1:5000/settings. The form should load.
    2. [Valid Submission]: Fill in the email and click "Update Settings". You should see a success message.
    3. [Invalid Token Submission]:
       a. Load the form.
       b. Use browser developer tools (right-click -> Inspect) to change the value of the hidden "csrf_token" input.
       c. Submit the form. You should get a "403 Forbidden" error.
    4. [Missing Token Submission]:
       a. Load the form.
       b. Use developer tools to delete the hidden "csrf_token" input field entirely.
       c. Submit the form. You should get a "403 Forbidden" error.
    5. [Token Replay Attack]:
       a. Submit the form successfully.
       b. Use the browser's "back" button to go back to the form page.
       c. Try to submit the form again without reloading the page.
       d. You should get a "403 Forbidden" error because the token was a one-time use token.
    """
    Task40.run(debug=True)