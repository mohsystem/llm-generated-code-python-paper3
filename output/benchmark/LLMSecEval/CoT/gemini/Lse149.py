from flask import Flask, request, redirect, url_for, escape

# In a real application, you would use a proper database.
# For this example, we use a simple in-memory list.
messages = []

def insert_user_message_in_db(username, message):
    """Simulates inserting a user message into a database."""
    if username and message:
        messages.append({'username': username, 'message': message})

def get_all_messages():
    """Simulates retrieving all messages from a database."""
    return messages

app = Flask(__name__)

@app.route('/')
def index():
    """Displays the main page with the message form and all posted messages."""
    # Build HTML for messages safely
    message_html = ""
    all_messages = get_all_messages()
    if not all_messages:
        message_html = "<p>No messages yet.</p>"
    else:
        for msg in all_messages:
            # Use escape() to prevent XSS vulnerabilities
            safe_username = escape(msg['username'])
            safe_message = escape(msg['message'])
            message_html += f"<p><strong>{safe_username}:</strong> {safe_message}</p>"

    # The main page template
    return f"""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Message Board</title>
    </head>
    <body>
        <h1>Post a Message</h1>
        <form action="/post" method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br>
            <label for="message">Message:</label><br>
            <textarea id="message" name="message" required></textarea><br><br>
            <input type="submit" value="Post">
        </form>
        <h2>Messages</h2>
        <div id="messages">
            {message_html}
        </div>
    </body>
    </html>
    """

@app.route('/post', methods=['POST'])
def post():
    """Handles new message submissions."""
    username = request.form.get('username')
    message = request.form.get('message')

    # Insert the message into our "database"
    insert_user_message_in_db(username, message)

    # Redirect the user back to the main page
    return redirect(url_for('index'))

def run_tests():
    """
    This function simulates test cases. In a real Flask app, you'd use a test client.
    Here, we'll just print instructions for manual testing.
    """
    print("Server is running at http://127.0.0.1:5000")
    print("Manual Test Cases to run in your browser:")
    print("1. Go to http://127.0.0.1:5000. You should see a form and 'No messages yet'.")
    print("2. Submit a message with username 'Alice' and message 'Hello World'. You should be redirected and see Alice's message.")
    print("3. Submit another message with username 'Bob' and message 'Hi Alice!'. You should see both messages displayed.")
    print("4. Submit a message with username 'Eve' and message '<b>bold</b>'. The output should show the literal tags '<b>bold</b>' and not bolded text, preventing XSS.")
    print("5. Submit a message with username 'Mallory' and message '<script>alert(\"xss\")</script>'. No alert box should appear, and the script tag should be displayed as text.")

if __name__ == '__main__':
    # This acts as the main method
    run_tests()
    # To run this code:
    # 1. pip install Flask
    # 2. python your_script_name.py
    # 3. Open your browser and follow the test case instructions.
    app.run(debug=True)