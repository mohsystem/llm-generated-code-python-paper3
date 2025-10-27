def unsubscribe_script(email: str) -> int:
    """
    Simulates a script that unsubscribes an email.
    Returns 0 for success, non-zero for failure.
    """
    print(f"-> Calling unsubscribe script for: {email}")
    # Simulate success for emails containing "success", failure otherwise.
    if "success" in email:
        print("-> Script returned 0 (success).")
        return 0
    else:
        print("-> Script returned 1 (failure).")
        return 1

def check_and_unsubscribe(email: str, database: set) -> int:
    """
    Checks if an email exists and attempts to unsubscribe if it does.
    Returns 1 if email exists and unsubscribe is successful, 0 otherwise.
    """
    print(f"Checking for email: {email}")
    if email not in database:
        print("Email not found in database.")
        return 0  # Email doesn't exist

    print("Email found in database.")
    if unsubscribe_script(email) == 0:
        return 1  # Unsubscribe script was successful
    else:
        return 0  # Unsubscribe script failed

def main():
    # Mock database
    email_database = {
        "user.success@example.com",
        "user.fail@example.com",
        "another.success@example.com"
    }

    # Test cases
    test_emails = [
        "not.in.db@example.com",        # Test Case 1: Email not in DB
        "user.success@example.com",     # Test Case 2: Email in DB, script succeeds
        "user.fail@example.com",        # Test Case 3: Email in DB, script fails
        "another.success@example.com",  # Test Case 4: Another email in DB, script succeeds
        "another.not.in.db@email.com"   # Test Case 5: Another email not in DB
    ]

    for i, email in enumerate(test_emails):
        print(f"--- Test Case {i + 1} ---")
        result = check_and_unsubscribe(email, email_database)
        print(f"Final Result: {result}\n")

if __name__ == "__main__":
    main()