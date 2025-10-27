import html

# Simulating a database with a list of dictionaries
message_database = []

def sanitize(input_string):
    """
    Sanitizes user input to prevent XSS attacks using html.escape.
    """
    if not isinstance(input_string, str):
        return ""
    return html.escape(input_string)

def insert_user_message_in_db(username, message):
    """
    Inserts a user's message into the simulated database.
    """
    global message_database
    entry = {"username": username, "message": message}
    message_database.append(entry)
    print(f"LOG: Message from '{username}' stored in DB.")

def post(username, message):
    """
    Simulates handling a POST request to submit a message.
    It gets username and message, sanitizes them, inserts them into the DB,
    and simulates a redirect.
    """
    # 1. Input validation
    if not username or not username.strip() or not message or not message.strip():
        print("ERROR: Username or message cannot be empty.")
        return

    # 2. Sanitize inputs to prevent XSS
    sanitized_username = sanitize(username)
    sanitized_message = sanitize(message)

    # 3. Insert into database
    insert_user_message_in_db(sanitized_username, sanitized_message)

    # 4. Redirect
    print("Redirecting user to the main page...\n")

def display_messages():
    """
    Displays all the messages currently stored in the database.
    """
    print("--- Displaying All Messages ---")
    if not message_database:
        print("No messages to display.")
    else:
        for entry in message_database:
            print(f"{entry['username']}: {entry['message']}")
    print("-----------------------------\n")

def main():
    """
    Main function to run test cases.
    """
    print("Initial State:")
    display_messages()

    # --- Test Cases ---
    print(">>> Running Test Cases <<<")

    # Test Case 1: Standard post
    post("Alice", "Hello World!")

    # Test Case 2: Another standard post
    post("Bob", "This is a test message.")

    # Test Case 3: Post with characters that need sanitization
    post("Charlie", "<script>alert('xss')</script>")

    # Test Case 4: Post with an empty message (should be rejected)
    post("David", "  ")

    # Test Case 5: Post from a user who posted before
    post("Alice", "I am posting again!")

    print(">>> Test Cases Finished <<<\n")

    print("Final State:")
    display_messages()

if __name__ == "__main__":
    main()