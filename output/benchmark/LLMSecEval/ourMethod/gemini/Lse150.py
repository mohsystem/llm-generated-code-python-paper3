import os
import re
from flask import Flask, request, redirect, url_for, render_template_string, flash
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

# --- Application Setup ---

# Rule #30: Never hard code secrets. Read them from external configuration.
# In a real application, this should be a truly random and secret string.
# For this example, we use a default but check for an environment variable first.
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'a-secure-default-secret-key-for-dev')
if SECRET_KEY == 'a-secure-default-secret-key-for-dev' and os.environ.get('FLASK_ENV') != 'development':
    print("WARNING: Using a default SECRET_KEY in a non-development environment!")

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['TESTING'] = False


# --- Mock Database ---

# This list will act as our in-memory database for messages.
MESSAGES_DB = []

def insert_user_message_in_db(username, message):
    """
    Simulates inserting a message into a database.
    Rule #9: For database access, use parameterized queries or safe ORM APIs.
    For example, with sqlite3:
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
    conn.commit()
    conn.close()
    """
    print(f"DATABASE: Inserting message from '{username}'.")
    MESSAGES_DB.append({'username': username, 'message': message})
    return True

def get_all_messages():
    """Simulates retrieving all messages from the database."""
    return MESSAGES_DB


# --- Forms and Validation ---

# Rule #1, #2, #4, #5: Validate every external input before use.
# Use allow lists and specific validators for type, length, and format.
class MessageForm(FlaskForm):
    """Defines the form for submitting a message with validation rules."""
    username = StringField(
        'Username',
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=25, message="Username must be between 3 and 25 characters."),
            # Rule #2: Use allow lists. Only allow alphanumeric chars and underscores.
            Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores.")
        ]
    )
    message = TextAreaField(
        'Message',
        validators=[
            DataRequired(message="Message cannot be empty."),
            Length(min=1, max=500, message="Message must be between 1 and 500 characters.")
        ]
    )
    submit = SubmitField('Post Message')


# --- HTML Template ---

# For a single-file example, the template is included as a string.
# In a real app, this would be in a separate 'templates/index.html' file.
# Note: Jinja2 (Flask's template engine) auto-escapes variables like
# {{ message.username }} by default, preventing XSS (CWE-79).
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Message Board</title>
    <style>
        body { font-family: sans-serif; margin: 2em; }
        .form-field { margin-bottom: 1em; }
        .error { color: red; font-size: 0.9em; }
        .flash { background-color: #d4edda; color: #155724; padding: 1em; margin-bottom: 1em; border: 1px solid #c3e6cb; border-radius: 4px; }
        .message { border: 1px solid #ccc; padding: 1em; margin-bottom: 1em; border-radius: 4px; }
        .message strong { color: #333; }
    </style>
</head>
<body>
    <h1>Post a Message</h1>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="flash">
          {% for msg in messages %}
            <p>{{ msg }}</p>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    <form method="POST" action="{{ url_for('index') }}">
        {{ form.hidden_tag() }} <!-- Renders CSRF token and other hidden fields -->
        
        <div class="form-field">
            {{ form.username.label }}<br>
            {{ form.username(size=30) }}
            {% for error in form.username.errors %}
                <span class="error">{{ error }}</span>
            {% endfor %}
        </div>
        
        <div class="form-field">
            {{ form.message.label }}<br>
            {{ form.message(rows=5, cols=40) }}
            {% for error in form.message.errors %}
                <span class="error">{{ error }}</span>
            {% endfor %}
        </div>
        
        <div>
            {{ form.submit() }}
        </div>
    </form>
    
    <hr>
    <h2>Messages</h2>
    {% for message in messages %}
        <div class="message">
            <strong>{{ message.username }}:</strong>
            <p>{{ message.message }}</p>
        </div>
    {% else %}
        <p>No messages yet.</p>
    {% endfor %}
</body>
</html>
"""

# --- Routes and Views ---

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Handles both displaying the main page with the form (GET)
    and processing the form submission (POST).
    """
    form = MessageForm()
    
    # The post() function logic is integrated here, as is common in Flask.
    # It's called when the user submits a message via POST.
    if form.validate_on_submit():
        # form.validate_on_submit() checks if it's a POST request and if the data is valid,
        # including the CSRF token. This is the primary security gate.
        
        # Gets the validated and sanitized username and message from the form request.
        username = form.username.data
        message = form.message.data
        
        # Calls the function to insert the message into the database.
        insert_user_message_in_db(username, message)
        
        flash('Your message has been posted successfully!', 'success')
        
        # Redirects the user back to the main page (Post/Redirect/Get pattern).
        # This prevents form resubmission if the user refreshes the page.
        return redirect(url_for('index'))
        
    # For a GET request or if form validation fails, render the page.
    # Any validation errors will be automatically available in the form object.
    all_messages = get_all_messages()
    return render_template_string(HTML_TEMPLATE, form=form, messages=all_messages)

# --- Main and Test Cases ---

def main():
    """Includes 5 test cases using Flask's test client."""
    
    global MESSAGES_DB
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for simpler testing
    
    with app.test_client() as client:
        print("\n--- Running Test Cases ---")
        
        # Test Case 1: GET request to the main page
        print("\n1. Testing GET request to the main page...")
        response = client.get('/')
        assert response.status_code == 200
        assert b"Post a Message" in response.data
        print("   ...PASSED")

        # Test Case 2: Valid message submission (POST)
        print("\n2. Testing valid message submission...")
        MESSAGES_DB = [] # Reset DB for clean test
        response = client.post('/', data={
            'username': 'testuser',
            'message': 'This is a test message.'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b"Your message has been posted successfully!" in response.data
        assert b"testuser" in response.data
        assert len(MESSAGES_DB) == 1
        assert MESSAGES_DB[0]['username'] == 'testuser'
        print("   ...PASSED")

        # Test Case 3: Submission with missing username
        print("\n3. Testing submission with missing username...")
        response = client.post('/', data={
            'username': '',
            'message': 'A message with no user.'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b"Username is required." in response.data
        assert len(MESSAGES_DB) == 1 # DB should not have changed
        print("   ...PASSED")
        
        # Test Case 4: Submission with a message that is too long
        print("\n4. Testing submission with an overly long message...")
        long_message = 'A' * 501
        response = client.post('/', data={
            'username': 'longposter',
            'message': long_message
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b"Message must be between 1 and 500 characters." in response.data
        assert len(MESSAGES_DB) == 1 # DB should not have changed
        print("   ...PASSED")

        # Test Case 5: Submission with invalid characters in username
        print("\n5. Testing submission with invalid username format...")
        response = client.post('/', data={
            'username': 'invalid-user!',
            'message': 'This message should be rejected.'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b"Username can only contain letters, numbers, and underscores." in response.data
        assert len(MESSAGES_DB) == 1 # DB should not have changed
        print("   ...PASSED")

        print("\n--- All tests passed! ---")


if __name__ == '__main__':
    # Check if a command-line argument 'test' is provided
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        main()
    else:
        print("Starting Flask server...")
        print("To run tests, execute: python your_script_name.py test")
        # In a real production environment, use a proper WSGI server like Gunicorn or uWSGI
        app.run(debug=True, port=5001)