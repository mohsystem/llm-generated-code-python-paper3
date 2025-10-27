# Simulates a database of subscribed emails for demonstration purposes.
email_database = {
    "user.success@example.com",
    "user.fail@example.com",
    "another.success@example.com",
    "test.user@domain.com"
}

def mock_unsubscribe_script(email: str) -> int:
    """
    Simulates an external script that unsubscribes an email.
    In a real-world scenario, this would be a call to an external service or script.
    Calling a function is much safer than using os.system() or subprocess.run(),
    which can be vulnerable to command injection if not handled properly.

    Args:
        email: The email to unsubscribe.

    Returns:
        0 for success, 1 for failure.
    """
    # This is a mock implementation.
    # It succeeds if the email contains "success" or "test", and fails otherwise.
    if email and ("success" in email or "test" in email):
        print(f"-> Mock script: Successfully unsubscribed {email}")
        return 0  # Success
    else:
        print(f"-> Mock script: Failed to unsubscribe {email}")
        return 1  # Failure

def unsubscribe_user(email: str) -> int:
    """
    Checks if an email exists and attempts to unsubscribe it.

    Args:
        email: The email address to check and unsubscribe.

    Returns:
        1 if the email exists and the unsubscribe script succeeds, otherwise 0.
    """
    # Input validation: ensure email is not None or empty.
    if not isinstance(email, str) or not email.strip():
        print(f"Processing '{email}': Invalid input.")
        return 0
    
    print(f"Processing '{email}':")

    # Step 1: Check if the email exists in the database.
    if email in email_database:
        print("-> Email found in the database.")
        # Step 2: If it exists, call the unsubscribe script.
        script_result = mock_unsubscribe_script(email)

        # Step 3: Check the script's return value.
        if script_result == 0:
            # Script succeeded, return 1.
            print("-> Result: 1 (Success)")
            return 1
        else:
            # Script failed, return 0.
            print("-> Result: 0 (Script Failed)")
            return 0
    else:
        # Email does not exist, return 0.
        print("-> Email not found in the database.")
        print("-> Result: 0")
        return 0

# Main function to run test cases
if __name__ == "__main__":
    test_emails = [
        "user.success@example.com",  # Test case 1: Email exists, script succeeds
        "user.fail@example.com",     # Test case 2: Email exists, script fails
        "not.found@example.com",     # Test case 3: Email does not exist
        "test.user@domain.com",      # Test case 4: Another success case
        None                         # Test case 5: Invalid None input
    ]

    for i, email in enumerate(test_emails, 1):
        print(f"\n--- Test Case {i} ---")
        result = unsubscribe_user(email)
        print(f"Final return value: {result}")