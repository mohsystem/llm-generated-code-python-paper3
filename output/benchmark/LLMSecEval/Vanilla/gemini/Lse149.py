# To run this code, you need to install the Flask library:
# pip install Flask
# Then, run the script and open http://127.0.0.1:5000/ in your web browser.

from flask import Flask, request, redirect, url_for, escape

# Using a class to encapsulate the application logic
class Lse149:
    def __init__(self):
        # In-memory "database"
        self.messages = []
        self.app = Flask(__name__)
        self.setup_routes()
        self.add_test_cases()

    def add_test_cases(self):
        """ 5 Test cases: Pre-populate the database """
        self.insert_user_message_in_db("Alice", "Hello from Python!")
        self.insert_user_message_in_db("Bob", "This is a Flask web application.")
        self.insert_user_message_in_db("Charlie", "Web development with Python is great.")
        self.insert_user_message_in_db("David", "Let's see the messages.")
        self.insert_user_message_in_db("Eve", "The form should work.")

    def insert_user_message_in_db(self, username, message):
        """Simulates inserting a message into the database."""
        if username and message:
            self.messages.append({'username': username, 'message': message})

    def setup_routes(self):
        self.app.add_url_rule('/', 'index', self.index)
        self.app.add_url_rule('/post', 'post', self.post, methods=['POST'])

    def index(self):
        """Displays the message submission form and all posted messages."""
        html = """
        <html><body>
            <h1>Post a Message</h1>
            <form action="/post" method="post">
                Username: <input type="text" name="username"><br>
                Message:  <input type="text" name="message"><br>
                <input type="submit" value="Post">
            </form>
            <hr><h1>Messages</h1>
            <ul>
        """
        # Display messages in reverse chronological order
        for msg in reversed(self.messages):
            safe_user = escape(msg['username'])
            safe_msg = escape(msg['message'])
            html += f'<li><b>{safe_user}:</b> {safe_msg}</li>'
        
        html += "</ul></body></html>"
        return html

    def post(self):
        """Handles new message submissions."""
        username = request.form.get('username')
        message = request.form.get('message')
        self.insert_user_message_in_db(username, message)
        return redirect(url_for('index'))

    def run(self):
        print("Python server started on port 5000. Open http://127.0.0.1:5000/")
        self.app.run(debug=False)

if __name__ == '__main__':
    web_app = Lse149()
    web_app.run()