import re
from typing import Set, Optional

# Simulates a database table of subscribed email addresses.
# Using a set for efficient lookups O(1) average time complexity.
email_database: Set[str] = {
    "test@example.com",
    "user1@domain.com",
    "another.user@service.net"
}

def is_valid_email(email: Optional[str]) -> bool:
    """
    Validates an email address against a standard regex and length constraints.

    Args:
        email: The email address string to validate.

    Returns:
        True if the email is valid, False otherwise.
    """
    if not email:
        return False
    # Limit email length to a reasonable size to prevent abuse
    if len(email) > 254:
        return False
    # A common regex for email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$'
    return re.match(email_regex, email) is not None

def unsubscribe(email: Optional[str], db: Set[str]) -> str:
    """
    Unsubscribes an email address by removing it from the database set.

    Args:
        email: The email address to unsubscribe.
        db: The set representing the email database.

    Returns:
        A status message indicating the result of the operation.
    """
    # Rule #1: Ensure all input is validated.
    if not is_valid_email(email):
        return "Invalid email address format."

    # The core logic of the function
    # The 'email' variable is now guaranteed to be a string due to the check above
    if email in db:
        db.remove(email)
        return f"Successfully unsubscribed {email}."
    else:
        return "Email address not found in the database."

def main():
    """Main function with test cases."""
    print("--- Test Cases ---")

    # Test Case 1: A valid email that exists in the database.
    email1 = "test@example.com"
    print(f"Attempting to unsubscribe: {email1}")
    print(f"Result: {unsubscribe(email1, email_database)}")
    print(f"Re-checking: {unsubscribe(email1, email_database)}") # Should now be not found
    print()

    # Test Case 2: A valid email that does not exist in the database.
    email2 = "nonexistent@example.com"
    print(f"Attempting to unsubscribe: {email2}")
    print(f"Result: {unsubscribe(email2, email_database)}")
    print()

    # Test Case 3: An invalid email address.
    email3 = "invalid-email"
    print(f"Attempting to unsubscribe: {email3}")
    print(f"Result: {unsubscribe(email3, email_database)}")
    print()

    # Test Case 4: A None input.
    email4 = None
    print("Attempting to unsubscribe: None")
    print(f"Result: {unsubscribe(email4, email_database)}")
    print()

    # Test Case 5: An empty string input.
    email5 = ""
    print("Attempting to unsubscribe: \"\"")
    print(f"Result: {unsubscribe(email5, email_database)}")
    print()

if __name__ == "__main__":
    main()