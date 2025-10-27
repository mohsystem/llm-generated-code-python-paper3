import sys

MAX_USERNAME_LENGTH = 50
MAX_MESSAGE_LENGTH = 280

# Simulated in-memory database
user_messages_db = {}

def insert_user_message_in_db(username, message):
    """
    Inserts a user's message into the simulated database.
    In a real application, this is where secure database interaction would happen.
    
    Args:
        username (str): The validated user's name.
        message (str): The validated message content.
    """
    print(f"DB: Inserting message for user '{username}'.")
    # SECURITY: In a real application, use parameterized queries (placeholders)
    # to prevent SQL injection. NEVER build a query using f-strings or string concatenation.
    # Example (psycopg2 for PostgreSQL):
    # cursor.execute("INSERT INTO messages (user, msg) VALUES (%s, %s)", (username, message))
    
    if username not in user_messages_db:
        user_messages_db[username] = []
    user_messages_db[username].append(message)

def post(username, message):
    """
    Simulates handling a POST request to submit a message.
    It gets the username and message, performs validation, calls the DB insert,
    and simulates a redirect.
    
    Args:
        username (str): The username from the request.
        message (str): The message from the request.
    
    Returns:
        A string indicating the result, simulating a redirect URL.
    """
    # SECURITY: Validate all user input before processing.
    # 1. Check for None or effectively empty strings.
    if not username or not username.strip():
        print("Error: Username cannot be empty.", file=sys.stderr)
        return "redirect:/main?error=invalid_username"
    
    if not message or not message.strip():
        print("Error: Message cannot be empty.", file=sys.stderr)
        return "redirect:/main?error=invalid_message"

    # 2. Enforce length limits.
    if len(username) > MAX_USERNAME_LENGTH:
        print("Error: Username is too long.", file=sys.stderr)
        return "redirect:/main?error=username_too_long"

    if len(message) > MAX_MESSAGE_LENGTH:
        print("Error: Message is too long.", file=sys.stderr)
        return "redirect:/main?error=message_too_long"
        
    # SECURITY: To prevent Cross-Site Scripting (XSS), user-provided content
    # should be properly HTML-escaped before being rendered on a web page.
    # e.g., using libraries like Jinja2 which auto-escape by default.
    # This function only handles storing data, not rendering it.

    insert_user_message_in_db(username, message)
    
    print("Success! Redirecting to the main page.")
    return "redirect:/main"

# In Python, we use the `if __name__ == "__main__"` block as the main entry point
# to simulate a form submission and run tests.
class Lse150:
    @staticmethod
    def main():
        """Main function to simulate a form and run test cases."""
        print("--- Running Test Cases ---")

        # Test Case 1: Valid submission
        print("\n--- Test Case 1: Valid submission ---")
        post("alice", "Hello, world!")

        # Test Case 2: Another valid submission from a different user
        print("\n--- Test Case 2: Another valid user ---")
        post("bob", "This is a test message.")

        # Test Case 3: Message is too long
        print("\n--- Test Case 3: Message too long ---")
        long_message = "a" * 300
        post("alice", long_message)

        # Test Case 4: Empty username
        print("\n--- Test Case 4: Empty username ---")
        post("  ", "This should fail.")

        # Test Case 5: Potentially malicious input
        print("\n--- Test Case 5: Input with special characters ---")
        post("charlie", "<script>alert('xss')</script>")

        print("\n--- Final Database State ---")
        for user, messages in user_messages_db.items():
            print(f"User: {user}")
            for msg in messages:
                print(f"  - {msg}")

if __name__ == "__main__":
    Lse150.main()