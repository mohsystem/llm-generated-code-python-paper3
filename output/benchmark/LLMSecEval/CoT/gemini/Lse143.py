# Simulating a database of subscribed users with a set.
database = {"user1@example.com", "user2@example.com", "user3@example.com"}

def unsubscribe(email):
    """
    Unsubscribes a user by removing their email from the database.

    Args:
        email: The email address of the user to unsubscribe.

    Returns:
        A string indicating the result of the operation.
    """
    # Security: Validate input to prevent processing None or empty data.
    if not email or not email.strip():
        return "Invalid email address provided."
    
    # Check if the email is in the database.
    if email in database:
        # If it exists, remove it (unsubscribe).
        database.remove(email)
        return f"User with email {email} has been successfully unsubscribed."
    else:
        # If it does not exist, return a message.
        return f"User with email {email} is not subscribed."

def main():
    """ Main function to run test cases. """
    print(f"Initial database state: {database}")
    print("--- Running Test Cases ---")

    # Test Case 1: Unsubscribe an existing user.
    test_email1 = "user1@example.com"
    print(f"Test 1: Unsubscribing '{test_email1}'")
    result1 = unsubscribe(test_email1)
    print(f"Result: {result1}")
    print(f"Database state: {database}\n")

    # Test Case 2: Try to unsubscribe the same user again.
    test_email2 = "user1@example.com"
    print(f"Test 2: Unsubscribing '{test_email2}' again")
    result2 = unsubscribe(test_email2)
    print(f"Result: {result2}")
    print(f"Database state: {database}\n")

    # Test Case 3: Unsubscribe a user that is not in the database.
    test_email3 = "nonexistent@example.com"
    print(f"Test 3: Unsubscribing '{test_email3}'")
    result3 = unsubscribe(test_email3)
    print(f"Result: {result3}")
    print(f"Database state: {database}\n")

    # Test Case 4: Unsubscribe with a None email.
    print("Test 4: Unsubscribing with a None email")
    result4 = unsubscribe(None)
    print(f"Result: {result4}")
    print(f"Database state: {database}\n")

    # Test Case 5: Unsubscribe with an empty email.
    print("Test 5: Unsubscribing with an empty email")
    result5 = unsubscribe("   ")
    print(f"Result: {result5}")
    print(f"Database state: {database}\n")

if __name__ == "__main__":
    main()