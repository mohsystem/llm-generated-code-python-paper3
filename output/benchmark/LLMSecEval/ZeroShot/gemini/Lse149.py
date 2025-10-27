import html

class Lse149:
    def __init__(self):
        # In-memory list to simulate a database
        self.database = []

    def insert_user_message_in_db(self, username, message):
        """
        Simulates inserting a user message into the database.
        In a real application, this function must use parameterized queries
        to prevent SQL injection.
        """
        # SQL INJECTION PREVENTION NOTE:
        # If using a real database (e.g., with sqlite3), the code would be:
        # cursor.execute(
        #     "INSERT INTO messages (username, message) VALUES (?, ?)",
        #     (username, message)
        # )
        # ORMs like SQLAlchemy also handle this securely by default.
        
        # Basic validation: do not insert empty or falsy data.
        if username and message:
            self.database.append({'username': username, 'message': message})

    def display_messages(self):
        """
        Simulates fetching all messages and rendering them as an HTML string.
        Calls html.escape() on all user-provided data to prevent XSS.
        """
        if not self.database:
            return "<h1>Messages</h1>\n<ul>\n<li>No messages yet.</li>\n</ul>"

        html_parts = ["<h1>Messages</h1>", "<ul>"]
        for msg in self.database:
            # Use html.escape to prevent Cross-Site Scripting (XSS)
            safe_username = html.escape(msg.get('username', ''))
            safe_message = html.escape(msg.get('message', ''))
            html_parts.append(f"<li><b>{safe_username}:</b> {safe_message}</li>")
        
        html_parts.append("</ul>")
        return "\n".join(html_parts)

    def route_post(self, username, message):
        """Simulates a request handler for the "/post" route."""
        print("--- Handling POST /post ---")
        print(f"Received: username={username}, message={message}")
        self.insert_user_message_in_db(username, message)
        print("-> Inserted data into DB.")
        print("-> Redirecting to /")
        print("-------------------------")

    def route_get(self):
        """Simulates a request handler for the "/" route."""
        print("--- Handling GET / ---")
        print("-> Displaying messages:")
        print(self.display_messages())
        print("----------------------")

def main():
    """Main function to run test cases."""
    app = Lse149()
    
    # --- 5 Test Cases ---

    print(">>> Test Case 1: Post a regular message")
    app.route_post("Alice", "Hello World!")
    app.route_get()

    print("\n>>> Test Case 2: Post another message")
    app.route_post("Bob", "This is a test.")
    app.route_get()

    print("\n>>> Test Case 3: Post a message with HTML characters (XSS attempt)")
    app.route_post("Eve", "<script>alert('xss')</script>")
    app.route_get()  # Output should show escaped HTML: &lt;script&gt;...

    print("\n>>> Test Case 4: Post a message with other special characters")
    app.route_post("Charlie", "Me & You > Them")
    app.route_get()  # Output should show escaped characters: Me &amp; You &gt; Them

    print("\n>>> Test Case 5: Post empty data (should be handled gracefully)")
    app.route_post("", "An empty username")
    app.route_post("David", "")
    print("-> View after invalid posts (should be unchanged):")
    app.route_get()

if __name__ == "__main__":
    main()