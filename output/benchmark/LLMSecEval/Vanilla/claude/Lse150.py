
from flask import Flask, request, redirect, render_template_string
import sqlite3
from datetime import datetime

app = Flask(__name__)

# HTML template for the main page with form
MAIN_PAGE_TEMPLATE = '''\n<!DOCTYPE html>\n<html>\n<head>\n    <title>Message Board</title>\n</head>\n<body>\n    <h1>Message Board</h1>\n    <form method="post" action="/post">\n        <label>Username: <input type="text" name="username" required></label><br><br>\n        <label>Message: <textarea name="message" required></textarea></label><br><br>\n        <input type="submit" value="Submit Message">\n    </form>\n    <h2>Recent Messages:</h2>\n    <ul>\n    {% for msg in messages %}\n        <li><strong>{{ msg[0] }}</strong>: {{ msg[1] }} <em>({{ msg[2] }})</em></li>\n    {% endfor %}\n    </ul>\n</body>\n</html>\n'''

def insert_user_message_in_db(username, message):
    """Insert user message into database"""
    conn = sqlite3.connect('messages.db')
    cursor = conn.cursor()
    
    # Create table if not exists
    cursor.execute('''\n        CREATE TABLE IF NOT EXISTS messages (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT NOT NULL,\n            message TEXT NOT NULL,\n            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP\n        )\n    ''')
    
    # Insert message
    cursor.execute(
        "INSERT INTO messages (username, message) VALUES (?, ?)",
        (username, message)
    )
    
    conn.commit()
    conn.close()

def get_messages():
    """Retrieve messages from database"""
    conn = sqlite3.connect('messages.db')
    cursor = conn.cursor()
    
    cursor.execute('''\n        CREATE TABLE IF NOT EXISTS messages (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT NOT NULL,\n            message TEXT NOT NULL,\n            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP\n        )\n    ''')
    
    cursor.execute("SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 10")
    messages = cursor.fetchall()
    conn.close()
    
    return messages

@app.route('/post', methods=['POST'])
def post():
    """Handle message submission"""
    # Get username and message from request
    username = request.form.get('username')
    message = request.form.get('message')
    
    # Insert message into database
    if username and message:
        insert_user_message_in_db(username, message)
    
    # Redirect to main page
    return redirect('/')

@app.route('/', methods=['GET'])
def main():
    """Display main page with form"""
    messages = get_messages()
    return render_template_string(MAIN_PAGE_TEMPLATE, messages=messages)

if __name__ == '__main__':
    # Test cases
    print("Running test cases...")
    
    # Initialize database
    conn = sqlite3.connect('messages.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS messages')
    conn.commit()
    conn.close()
    
    # Test case 1
    insert_user_message_in_db("John", "Hello World")
    print("Test 1: Inserted John's message")
    
    # Test case 2
    insert_user_message_in_db("Alice", "Test message")
    print("Test 2: Inserted Alice's message")
    
    # Test case 3
    insert_user_message_in_db("Bob", "Another test")
    print("Test 3: Inserted Bob's message")
    
    # Test case 4
    insert_user_message_in_db("Charlie", "Fourth message")
    print("Test 4: Inserted Charlie's message")
    
    # Test case 5
    insert_user_message_in_db("David", "Last test message")
    print("Test 5: Inserted David's message")
    
    # Retrieve and display all messages
    messages = get_messages()
    print("\\nAll messages in database:")
    for msg in messages:
        print(f"{msg[0]}: {msg[1]} ({msg[2]})")
    
    print("\\nStarting Flask server...")
    app.run(debug=True)
