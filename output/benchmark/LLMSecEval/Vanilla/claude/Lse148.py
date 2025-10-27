
from flask import Flask, request, redirect, render_template_string
from datetime import datetime

app = Flask(__name__)

# In-memory storage for messages (simulating database)
messages = []

class Message:
    def __init__(self, username, message):
        self.username = username
        self.message = message
        self.timestamp = datetime.now()

def insert_user_message_in_db(username, message):
    """Insert user message in database"""
    messages.append(Message(username, message))
    print(f"Message inserted: {username} - {message}")

@app.route('/post', methods=['POST'])
def post():
    """Handle post request when user submits a message"""
    username = request.form.get('username', '')
    message = request.form.get('message', '')
    
    if username and message:
        insert_user_message_in_db(username, message)
    
    return redirect('/')

@app.route('/', methods=['GET'])
def get():
    """Display all messages"""
    html_template = '''\n    <html>\n    <body>\n        <h2>Messages</h2>\n        {% for msg in messages %}\n            <p><strong>{{ msg.username }}:</strong> {{ msg.message }}</p>\n        {% endfor %}\n        <hr>\n        <form method="post" action="/post">\n            Username: <input type="text" name="username"><br>\n            Message: <input type="text" name="message"><br>\n            <input type="submit" value="Send">\n        </form>\n    </body>\n    </html>\n    '''
    return render_template_string(html_template, messages=messages)

def main():
    # Test cases
    print("Test Case 1: Adding first message")
    insert_user_message_in_db("Alice", "Hello World!")
    
    print("\\nTest Case 2: Adding second message")
    insert_user_message_in_db("Bob", "Hi there!")
    
    print("\\nTest Case 3: Adding message with special characters")
    insert_user_message_in_db("Charlie", "Test @#$ message!")
    
    print("\\nTest Case 4: Adding empty username")
    insert_user_message_in_db("", "Anonymous message")
    
    print("\\nTest Case 5: Adding long message")
    insert_user_message_in_db("David", "This is a very long message to test the system's ability to handle lengthy text content.")
    
    print("\\nAll messages:")
    for msg in messages:
        print(f"{msg.username}: {msg.message}")

if __name__ == '__main__':
    main()
    # Uncomment to run Flask app
    # app.run(debug=True)
