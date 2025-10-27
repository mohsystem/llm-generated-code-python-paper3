import html

# In a real web application, this would be a database.
# Here, we use a list to simulate a database for demonstration.
message_database = []

def sanitize(input_str):
    """
    Sanitizes user input to prevent Cross-Site Scripting (XSS) by escaping HTML special characters.
    This uses Python's built-in html.escape function.
    """
    if not input_str:
        return ""
    return html.escape(input_str)

def insert_user_message_in_db(username, message):
    """
    Simulates inserting a user's message into the database.
    This method is safe from SQL Injection because it's not constructing a raw SQL query.
    In a real application, this would use parameterized queries.
    """
    print(f"[DB] Inserting message for user: {username}")
    message_database.append({'username': username, 'message': message})

def post(username, message):
    """
    Simulates handling a POST request from a user submitting a message.
    """
    print("\n--- Handling POST Request ---")
    
    # Security: Validate input to prevent empty submissions.
    if not username or not username.strip() or not message or not message.strip():
        print("Error: Username and message cannot be empty.")
        print("--- End POST Request ---")
        return

    # The data is stored raw and sanitized only upon display.
    insert_user_message_in_db(username.strip(), message.strip())

    # Simulate redirecting the user back to the main page.
    print("Action: Message posted successfully.")
    print("Action: Redirecting user to main page...")
    print("--- End POST Request ---")

def show_main_page():
    """
    Simulates rendering the main page with a message form and existing messages.
    """
    print("\n======================================")
    print("         Welcome to the Main Page")
    print("======================================")

    print("\n--- Message Board ---")
    if not message_database:
        print("(No messages yet)")
    else:
        for msg in message_database:
            # Security: Sanitize output to prevent XSS.
            safe_username = sanitize(msg['username'])
            safe_message = sanitize(msg['message'])
            print(f"{safe_username}: {safe_message}")
    print("--- End of Messages ---")

    # Simulate the submission form.
    print("\n--- Submit a New Message (Form) ---")
    print("[ Username: ___________ ]")
    print("[ Message:  ___________ ]")
    print("[ [SUBMIT] ]")
    print("======================================\n")

def main():
    """ Main function to run test cases. """
    # Initially, show the empty main page.
    show_main_page()

    # --- Test Cases ---

    # Test Case 1: A standard, valid post.
    print(">>> TEST CASE 1: Standard Post")
    post("Alice", "Hello everyone!")
    show_main_page()

    # Test Case 2: Another standard post.
    print(">>> TEST CASE 2: Another User Post")
    post("Bob", "Hi Alice, how are you?")
    show_main_page()

    # Test Case 3: A post with special HTML characters (XSS attempt).
    print(">>> TEST CASE 3: XSS Attempt")
    post("Mallory", "<script>alert('pwned')</script>")
    show_main_page()

    # Test Case 4: A post with an empty message (should be rejected).
    print(">>> TEST CASE 4: Empty Message")
    post("Charlie", "      ")
    show_main_page()

    # Test Case 5: A post with a mix of content.
    print(">>> TEST CASE 5: Mixed Content")
    post("David", "I think 5 > 3 & 2 < 4. What do you think?")
    show_main_page()

if __name__ == "__main__":
    main()