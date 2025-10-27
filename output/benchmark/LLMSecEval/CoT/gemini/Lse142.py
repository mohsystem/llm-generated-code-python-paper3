def unsubscribe(database: set, email: str) -> str:
    """
    Simulates unsubscribing an email address from a database.
    The database is represented by a set of strings.

    Args:
        database: The set of subscribed email addresses. This set will be modified.
        email: The email address to unsubscribe.

    Returns:
        A status message indicating success or failure.
    """
    # Basic input validation
    if not email or not isinstance(email, str) or email.strip() == "":
        return "Invalid email address provided."

    # Normalize email to lowercase for case-insensitive comparison
    normalized_email = email.lower()

    # Check if the email is in the database and remove it
    if normalized_email in database:
        database.remove(normalized_email)
        return f"Successfully unsubscribed {email}."
    else:
        return f"Email address {email} not found in the database."

def main():
    # 1. Initialize the simulated database with lowercase emails
    email_database = {
        "user1@example.com",
        "user2@example.com",
        "subscriber@test.com",
        "another.user@domain.org"
    }
    
    print(f"Initial database: {email_database}")

    # 2. Define test cases
    test_emails = [
        "user1@example.com",      # Case 1: Email exists and should be removed.
        "user99@example.com",     # Case 2: Email does not exist.
        "user1@example.com",      # Case 3: Email should now be gone after the first test.
        "SUBSCRIBER@TEST.COM",  # Case 4: Test case-insensitivity.
        ""                        # Case 5: Empty string test.
    ]

    # 3. Run test cases
    for email in test_emails:
        print(f"\nAttempting to unsubscribe: '{email}'")
        result = unsubscribe(email_database, email)
        print(f"Result: {result}")
        print(f"Current database: {email_database}")

if __name__ == "__main__":
    main()