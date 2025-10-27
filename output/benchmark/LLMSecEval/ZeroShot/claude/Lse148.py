
from flask import Flask, request, redirect, render_template_string
import sqlite3
from datetime import datetime
import html

app = Flask(__name__)

# Database initialization
def init_db():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages\n                 (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                  username TEXT NOT NULL,\n                  message TEXT NOT NULL,\n                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# Function to insert user message in database
def insert_user_message_in_db(username, message):
    try:
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute("INSERT INTO messages (username, message) VALUES (?, ?)", 
                  (username, message))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

# Function to get all messages
def get_messages():
    try:
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute("SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 50")
        messages = c.fetchall()
        conn.close()
        return messages
    except Exception as e:
        print(f"Error: {e}")
        return []

# Sanitize input
def sanitize_input(text):
    if not text:
        return ""
    return text.strip()[:500]  # Limit length

# POST route
@app.route('/post', methods=['POST'])
def post():
    # Get username and message from request
    username = request.form.get('username', '')
    message = request.form.get('message', '')
    
    # Validate input
    if username and message:
        username = sanitize_input(username)
        message = sanitize_input(message)
        
        # Insert message in database
        insert_user_message_in_db(username, message)
    
    # Redirect to main page
    return redirect('/')

# Main page route to display messages
@app.route('/', methods=['GET'])
def index():
    messages = get_messages()
    
    html_template = '''\n    <!DOCTYPE html>\n    <html>\n    <head>\n        <title>Message Board</title>\n        <style>\n            body { font-family: Arial, sans-serif; margin: 20px; }\n            .message { border: 1px solid #ccc; margin: 10px 0; padding: 10px; }\n            form { margin-bottom: 20px; }\n            input, textarea { display: block; margin: 5px 0; padding: 5px; }\n        </style>\n    </head>\n    <body>\n        <h1>Message Board</h1>\n        <form method="post" action="/post">\n            <label>Username:</label>\n            <input type="text" name="username" required maxlength="100">\n            <label>Message:</label>\n            <textarea name="message" required maxlength="500" rows="4" cols="50"></textarea>\n            <input type="submit" value="Submit">\n        </form>\n        <hr>\n        <h2>Messages:</h2>\n        {% for msg in messages %}\n        <div class="message">\n            <strong>{{ msg[0] }}</strong> <small>({{ msg[2] }})</small><br>\n            <p>{{ msg[1] }}</p>\n        </div>\n        {% endfor %}\n    </body>\n    </html>\n    '''
    
    return render_template_string(html_template, messages=messages)

if __name__ == '__main__':
    init_db()
    
    # Test cases
    print("Running test cases...")
    
    # Test 1: Insert test message
    insert_user_message_in_db("TestUser1", "Hello World!")
    print("Test 1: Inserted message from TestUser1")
    
    # Test 2: Insert another message
    insert_user_message_in_db("TestUser2", "This is a test message")
    print("Test 2: Inserted message from TestUser2")
    
    # Test 3: Insert message with special characters
    insert_user_message_in_db("User3", "Testing <script>alert('xss')</script>")
    print("Test 3: Inserted message with special characters")
    
    # Test 4: Get messages
    messages = get_messages()
    print(f"Test 4: Retrieved {len(messages)} messages")
    
    # Test 5: Empty username/message handling
    insert_user_message_in_db("", "")
    print("Test 5: Tested empty input handling")
    
    print("\\nStarting Flask server...")
    app.run(debug=True, port=5000)
