import html

# In-memory list to act as a mock database
message_database = []

def html_escape(input_string):
    """
    Sanitizes user input to prevent Cross-Site Scripting (XSS) attacks
    by escaping HTML special characters using Python's built-in library.
    
    Args:
        input_string: The raw string from the user.
    
    Returns:
        A sanitized string safe for HTML rendering.
    """
    if not isinstance(input_string, str):
        return ""
    return html.escape(input_string)

def insert_user_message_in_db(username, message):
    """
    Inserts a user's message into our mock database.
    Input is stored raw. Sanitization happens on display.
    
    Args:
        username: The name of the user posting the message.
        message: The content of the message.
    """
    # Basic input validation
    if not username or not message:
        print("Error: Username and message cannot be empty.")
        return
    if len(username) > 50 or len(message) > 280:
        print("Error: Username or message is too long.")
        return

    message_database.append({'username': username, 'content': message})
    print(f"Message from '{username}' stored successfully.")

def post(username, message):
    """
    Simulates a user submitting a post. Gets data from the "request",
    stores it, and "redirects".
    
    Args:
        username: The name of the user from the request.
        message: The message content from the request.
    """
    print(f"\n--- Received new post from user: {username} ---")
    insert_user_message_in_db(username, message)
    print("...Redirecting user to the main page.")

def display_all_messages():
    """
    Displays all messages from the mock database in a secure manner.
    """
    print("\n--- Main Page: All Messages ---")
    if not message_database:
        print("No messages to display.")
    else:
        for msg in message_database:
            # Sanitize output just before displaying it to prevent stored XSS.
            safe_username = html_escape(msg.get('username', ''))
            safe_content = html_escape(msg.get('content', ''))
            print(f"User: {safe_username}")
            print(f"Message: {safe_content}")
            print("---------------------------------")


if __name__ == "__main__":
    # --- Test Cases ---

    # Test Case 1: Normal post
    post("Alice", "Hello, world! This is my first message.")

    # Test Case 2: Another normal post
    post("Bob", "This is a great platform!")

    # Test Case 3: Post with special HTML characters
    post("Charlie", "My thoughts on C++: it's great for when you need <performance> & control.")

    # Test Case 4: A malicious post attempting an XSS attack
    post("Eve", "<script>alert('You have been hacked!');</script>")

    # Test Case 5: Post with quotes
    post("David", "He said, \"It's a 'nice' day.\"")

    # Display all the messages at the end
    display_all_messages()