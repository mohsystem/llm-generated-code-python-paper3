import re
import subprocess

# Mock database of subscribed emails. In a real application, this would be a database call.
EMAIL_DATABASE = {
    "test@example.com",
    "user1@test.com",
    "fail@example.com",
    "subscriber@newsletter.org"
}

# A simple email validation regex.
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def email_exists(email: str) -> bool:
    """
    Simulates checking if an email exists in the database.
    """
    # SECURITY: In a real application, use a parameterized query or an ORM
    # to prevent SQL injection when querying the database.
    # e.g., cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s", (email,))
    return email in EMAIL_DATABASE

def run_unsubscribe_script(email: str) -> int:
    """
    Simulates running an external script to unsubscribe an email.
    Returns 0 on success, a non-zero value on failure.
    """
    # SECURITY: Never build a command string using f-strings or concatenation with user input.
    # This prevents command injection. Pass the email as a separate argument.
    # e.g., subprocess.run(["/path/to/script.sh", email], check=True)
    
    print(f"   -> Running unsubscribe script for: {email}")

    # Mock logic: script fails if the email contains "fail".
    if "fail" in email:
        print("   -> Script failed.")
        return -1  # Non-zero indicates failure
    
    print("   -> Script succeeded.")
    return 0  # 0 indicates success

def unsubscribe_email(email: str) -> int:
    """
    Checks if an email exists and unsubscribes it.
    
    Returns:
        1 if the email existed and the unsubscribe script succeeded.
        0 in all other cases (email not found, invalid email, or script failure).
    """
    # 1. Input Validation
    if not isinstance(email, str) or not EMAIL_REGEX.match(email):
        print(f"Input '{email}' is invalid.")
        return 0

    # 2. Check if email exists in the database.
    if not email_exists(email):
        print(f"Email '{email}' not found in database.")
        return 0
    
    print(f"Email '{email}' found. Attempting to unsubscribe.")
    # 3. Call the unsubscribe script.
    script_result = run_unsubscribe_script(email)

    # 4. Check script result and return final status.
    if script_result == 0:
        return 1  # Script succeeded
    else:
        return 0  # Script failed

def main():
    """ Main function with test cases """
    test_cases = {
        "test@example.com": 1,        # Exists, script will succeed
        "fail@example.com": 0,        # Exists, script will fail
        "notfound@example.com": 0,    # Does not exist
        "invalid-email": 0,           # Invalid format
        "subscriber@newsletter.org": 1 # Exists, script will succeed
    }

    for i, (email, expected) in enumerate(test_cases.items()):
        print(f"--- Test Case {i + 1}: {email} ---")
        result = unsubscribe_email(email)
        print(f"Result: {result} (Expected: {expected})")
        print("Status: PASSED" if result == expected else "Status: FAILED")
        print()

if __name__ == "__main__":
    main()