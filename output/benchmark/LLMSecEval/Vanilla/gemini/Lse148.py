# Simulating a database with a list of dictionaries
messages_db = []

def insert_user_message_in_db(username, message):
    """Inserts a user's message into our simulated database."""
    message_entry = {"username": username, "message": message}
    messages_db.append(message_entry)
    print(f"DB: Message from '{username}' stored successfully.")

def post(username, message):
    """
    Simulates a user submitting a message.
    It gets the username and message, inserts it into the DB, and redirects.
    """
    print(f"\nPOST request received for user: {username}")
    insert_user_message_in_db(username, message)
    # Simulate redirecting the user
    print("Action: Redirecting user to the main page...")

def display_messages():
    """Displays all the messages currently stored in the database."""
    print("\n--- Main Message Board ---")
    if not messages_db:
        print("No messages to display.")
    else:
        for msg in messages_db:
            print(f"{msg['username']}: {msg['message']}")
    print("--------------------------")

def main():
    """Main function to run test cases."""
    # --- 5 Test Cases ---

    # Test Case 1
    post("Alice", "Hello, world!")

    # Test Case 2
    post("Bob", "This is my first post.")

    # Test Case 3
    post("Charlie", "Does this thing work?")

    # Test Case 4
    post("Alice", "I'm posting again!")

    # Test Case 5
    post("Dave", "Hi everyone!")

    # Now, display all the messages that have been posted.
    display_messages()

if __name__ == "__main__":
    main()