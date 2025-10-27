import html
import threading
from flask import Flask, request, redirect, url_for

# In-memory "database"
messages = []
# Lock for thread-safe access to the messages list
lock = threading.Lock()

# Max lengths for input validation
MAX_USERNAME_LENGTH = 50
MAX_MESSAGE_LENGTH = 280

app = Flask(__name__)

def insert_user_message_in_db(username, message):
    """Inserts a user message into the in-memory database."""
    with lock:
        messages.append({'username': username, 'message': message})

def get_all_messages():
    """Retrieves all messages from the in-memory database."""
    with lock:
        # Return a copy to avoid issues with modification during iteration
        return list(messages)

@app.route('/')
def index():
    """Displays the main page with the message form and all posted messages."""
    all_messages = get_all_messages()
    
    # Building HTML response
    response_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Message Board</title>
        <style>
            body {{ font-family: sans-serif; margin: 2em; }}
            .message {{ border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 5px; }}
            .message-user {{ font-weight: bold; }}
            .message-text {{ margin-top: 5px; white-space: pre-wrap; word-wrap: break-word; }}
        </style>
    </head>
    <body>
        <h1>Post a Message</h1>
        <form action="/post" method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required maxlength="{MAX_USERNAME_LENGTH}"><br><br>
            <label for="message">Message:</label><br>
            <textarea id="message" name="message" rows="4" cols="50" required maxlength="{MAX_MESSAGE_LENGTH}"></textarea><br><br>
            <input type="submit" value="Submit">
        </form>
        
        <h2>Messages</h2>
    """

    # Display messages safely, newest first
    for msg in reversed(all_messages):
        # html.escape is crucial for preventing Cross-Site Scripting (XSS)
        safe_username = html.escape(msg['username'])
        safe_message = html.escape(msg['message'])
        response_html += f"""
        <div class="message">
            <div class="message-user">{safe_username}</div>
            <div class="message-text">{safe_message}</div>
        </div>
        """
    
    response_html += "</body></html>"
    return response_html

@app.route('/post', methods=['POST'])
def post_message():
    """Handles new message submissions."""
    username = request.form.get('username', '').strip()
    message = request.form.get('message', '').strip()

    # Input validation
    if not username or not message:
        return "Username and message cannot be empty.", 400
    
    if len(username) > MAX_USERNAME_LENGTH:
        return f"Username exceeds maximum length of {MAX_USERNAME_LENGTH} characters.", 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return f"Message exceeds maximum length of {MAX_MESSAGE_LENGTH} characters.", 400

    # Insert into database
    insert_user_message_in_db(username, message)
    
    # Redirect to the main page
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Add 5 test cases
    insert_user_message_in_db('Alice', 'Hello, world!')
    insert_user_message_in_db('Bob', 'This is a test message.')
    insert_user_message_in_db('Charlie', 'Flask is cool.')
    insert_user_message_in_db('David', 'Remember to escape user input!')
    insert_user_message_in_db('Eve', '<script>alert("xss")</script>')
    
    # Running the app
    # In a production environment, use a proper WSGI server like Gunicorn or uWSGI
    # To run: pip install Flask
    print("Server starting on http://localhost:8080")
    app.run(host='0.0.0.0', port=8080)