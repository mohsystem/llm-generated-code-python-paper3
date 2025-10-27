def unsubscribe(database: set, email: str) -> str:
    """
    Checks if an email is in the database and removes it if found.

    :param database: A set of strings representing the email database.
    :param email: The email address to unsubscribe.
    :return: A string indicating the result of the operation.
    """
    if email in database:
        database.remove(email)
        return f"{email} has been unsubscribed successfully."
    else:
        return f"{email} is not in the database."

def main():
    # Simulate a database with a set
    email_database = {"user1@example.com", "user2@example.com", "user3@example.com"}
    print(f"Initial database: {email_database}")

    # --- 5 Test Cases ---
    test_emails = [
        "user2@example.com",     # Case 1: Unsubscribe an existing email.
        "user4@example.com",     # Case 2: Try to unsubscribe an email that does not exist.
        "user1@example.com",     # Case 3: Unsubscribe another existing email.
        "user2@example.com",     # Case 4: Try to unsubscribe the first email again.
        "user3@example.com"      # Case 5: Unsubscribe the last remaining email.
    ]

    for i, email in enumerate(test_emails):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Attempting to unsubscribe: {email}")
        result = unsubscribe(email_database, email)
        print(f"Result: {result}")
        print(f"Current database: {email_database}")

if __name__ == "__main__":
    main()