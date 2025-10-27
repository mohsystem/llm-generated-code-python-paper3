import html

# Simulating a database with an in-memory list
message_database = []
MAX_USERNAME_LENGTH = 50
MAX_MESSAGE_LENGTH = 280

def insert_user_message_in_db(username, message):
    """
    Inserts a user message into our simulated database.
    This function demonstrates validation and sanitization.
    """
    # Rule #1: Ensure all input is validated
    if not username or not username.strip() or len(username) > MAX_USERNAME_LENGTH:
        print("Error: Invalid username.")
        return False
    if not message or not message.strip() or len(message) > MAX_MESSAGE_LENGTH:
        print("Error: Invalid message.")
        return False
    
    # Sanitize input before storing. html.escape is a safe way to prevent XSS.
    # Rule #2: Use safer alternatives.
    sanitized_username = html.escape(username.strip())
    sanitized_message = html.escape(message.strip())

    message_entry = {
        "username": sanitized_username,
        "message": sanitized_message
    }
    message_database.append(message_entry)
    print(f"Message from '{sanitized_username}' stored successfully.")
    return True

def post(username, message):
    """
    This function is called when a user submits a message.
    """
    print("\n--- Handling post request ---")
    # It gets the username and message from the request (passed as parameters here)
    # It calls the insert_user_message_in_db() function
    success = insert_user_message_in_db(username, message)

    if success:
        # It redirects the user to the main page (simulated)
        print("Redirecting user to the main page...")
    else:
        print("Post failed. Not redirecting.")

def get_messages_from_db():
    """
    Retrieves all messages from the database for display.
    """
    return message_database

def display_messages():
    """
    Displays all messages currently in the database.
    """
    print("\n--- Displaying All Messages ---")
    messages = get_messages_from_db()
    if not messages:
        print("No messages to display.")
    else:
        for msg in messages:
            # Output is already sanitized from when it was inserted
            print(f"{msg['username']}: {msg['message']}")
    print("-----------------------------\n")

def main():
    """
    Main function with 5 test cases.
    """
    # --- 5 Test Cases ---

    # Test Case 1: Valid post
    post("Alice", "Hello, world!")
    display_messages()

    # Test Case 2: Another valid post
    post("Bob", "This is a test message.")
    display_messages()

    # Test Case 3: Invalid post (empty message)
    post("Charlie", " ")
    display_messages()

    # Test Case 4: Invalid post (username too long)
    long_username = "user" * 20 
    post(long_username, "My username is too long.")
    display_messages()
    
    # Test Case 5: Post with characters that should be sanitized
    post("Eve", "<script>alert('XSS')</script>")
    display_messages()


if __name__ == "__main__":
    main()