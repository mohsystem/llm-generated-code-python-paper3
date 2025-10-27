import re
import subprocess

# A mock database of email addresses.
EMAIL_DATABASE = {
    "user1@example.com",
    "success@example.com",
    "fail@example.com"
}

# A simple regex for email validation.
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$")
MAX_EMAIL_LENGTH = 254

def is_valid_email(email: str) -> bool:
    """
    Validates an email address format and length.
    :param email: The email string to validate.
    :return: True if the email is valid, False otherwise.
    """
    if not isinstance(email, str) or not email or len(email) > MAX_EMAIL_LENGTH:
        return False
    return EMAIL_REGEX.match(email) is not None

def email_exists_in_db(email: str) -> bool:
    """
    Checks if an email exists in the mock database.
    :param email: The email to check.
    :return: True if the email exists, False otherwise.
    """
    # In a real application, this would query a database.
    return email in EMAIL_DATABASE

def call_unsubscribe_script(email: str) -> int:
    """
    Simulates calling an external script to unsubscribe an email.
    :param email: The email to unsubscribe.
    :return: 0 for success, non-zero for failure.
    """
    print(f"Simulating call to unsubscribe script for: {email}")
    # Security Note: In a real-world application, never use shell=True with user input.
    # Pass arguments as a list to subprocess.run to prevent command injection.
    # try:
    #     result = subprocess.run(
    #         ["/path/to/unsubscribe.sh", email],
    #         capture_output=True, text=True, check=False, timeout=10
    #     )
    #     return result.returncode
    # except FileNotFoundError:
    #     print("Error: Unsubscribe script not found.")
    #     return 127
    # except Exception as e:
    #     print(f"An error occurred: {e}")
    #     return 1

    # Mock logic: script fails for a specific email for testing purposes.
    if email == "fail@example.com":
        print("Mock script simulation: FAILED.")
        return 1  # Simulate failure
    
    print("Mock script simulation: SUCCESS.")
    return 0  # Simulate success

def process_unsubscribe_request(email: str) -> int:
    """
    Processes an unsubscribe request based on the specified logic.
    :param email: The email address to process.
    :return: 1 if the email exists and is successfully unsubscribed, 0 otherwise.
    """
    # 1. Rule#1: Ensure all input is validated.
    if not is_valid_email(email):
        return 0

    # 2. Check if email exists in the database.
    if email_exists_in_db(email):
        # 3. If it exists, call the unsubscribe script.
        script_result = call_unsubscribe_script(email)
        
        # 4. If the script returns 0, it was a success.
        if script_result == 0:
            return 1  # Success
        else:
            return 0  # Script failed
    else:
        # Email does not exist.
        return 0

def main():
    """Main function with test cases."""
    test_emails = [
        "success@example.com",  # Case 1: Exists, script succeeds -> should return 1
        "fail@example.com",     # Case 2: Exists, script fails -> should return 0
        "notfound@example.com", # Case 3: Does not exist -> should return 0
        "invalid-email",        # Case 4: Invalid format -> should return 0
        ""                      # Case 5: Empty string -> should return 0
    ]

    for email in test_emails:
        print(f"\n--- Processing test case for: '{email}' ---")
        result = process_unsubscribe_request(email)
        print(f"Result for '{email}': {result}")
        print("----------------------------------------")

if __name__ == "__main__":
    main()