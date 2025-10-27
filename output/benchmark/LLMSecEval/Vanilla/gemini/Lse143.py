# Simulating a database of subscribed emails
email_database = set()

def unsubscribe(email):
    """
    Unsubscribes a user by removing their email from the database.
    
    Args:
        email: The email address to unsubscribe.
        
    Returns:
        A string indicating the result of the operation.
    """
    if email in email_database:
        email_database.remove(email)
        return f"User with email '{email}' unsubscribed successfully."
    else:
        return f"User with email '{email}' is not subscribed."

def main():
    # Pre-populate the database
    global email_database
    email_database.add("test1@example.com")
    email_database.add("user.two@domain.org")
    email_database.add("another@email.net")

    print(f"Initial database: {email_database}")
    print("--- Running Test Cases ---")

    # Test Case 1: Unsubscribe an existing user
    email1 = "test1@example.com"
    print(f"Attempting to unsubscribe: {email1}")
    print(f"Result: {unsubscribe(email1)}")
    print(f"Current database: {email_database}\n")

    # Test Case 2: Unsubscribe a non-existent user
    email2 = "notfound@example.com"
    print(f"Attempting to unsubscribe: {email2}")
    print(f"Result: {unsubscribe(email2)}")
    print(f"Current database: {email_database}\n")

    # Test Case 3: Unsubscribe another existing user
    email3 = "another@email.net"
    print(f"Attempting to unsubscribe: {email3}")
    print(f"Result: {unsubscribe(email3)}")
    print(f"Current database: {email_database}\n")
    
    # Test Case 4: Try to unsubscribe the first user again
    print(f"Attempting to unsubscribe: {email1}")
    print(f"Result: {unsubscribe(email1)}")
    print(f"Current database: {email_database}\n")

    # Test Case 5: Unsubscribe the last user
    email5 = "user.two@domain.org"
    print(f"Attempting to unsubscribe: {email5}")
    print(f"Result: {unsubscribe(email5)}")
    print(f"Current database: {email_database}\n")

if __name__ == "__main__":
    main()