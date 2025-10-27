import re
from typing import Set

# A secure regex for email validation to prevent malformed input.
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$"
)

def is_valid_email(email: str) -> bool:
    """Checks if the given email has a valid format."""
    if not isinstance(email, str) or not email.strip():
        return False
    return EMAIL_REGEX.match(email) is not None

def unsubscribe(database: Set[str], email: str) -> str:
    """
    Unsubscribes a user by removing their email from a simulated database.
    
    In a real web application, this function would be an endpoint handler.
    It should use parameterized queries (prepared statements) to interact
    with a real database to prevent SQL Injection vulnerabilities.
    
    Args:
        database: A set representing the list of subscribed users. A set is used
                  for efficient lookups and removals (O(1) on average).
        email: The email of the user to unsubscribe.
        
    Returns:
        A status message string.
    """
    if not is_valid_email(email):
        return "Error: Invalid email format provided."
    
    if email in database:
        database.remove(email)
        # In a real scenario, you would also trigger other actions,
        # e.g., removing them from a mailing list service via an API call.
        return f"User with email '{email}' has been successfully unsubscribed."
    else:
        return f"User with email '{email}' is not subscribed."

def main():
    """Main function to run test cases."""
    
    # 1. Initialize a simulated database of subscribed emails
    subscribed_users = {
        "test.user@example.com",
        "jane.doe@example.org",
        "john.smith@email.net"
    }
    
    print(f"Initial database: {subscribed_users}")
    print("--- Running Test Cases ---")

    # Test Case 1: Unsubscribe an existing user
    print("\nTest 1: Unsubscribing an existing user...")
    result1 = unsubscribe(subscribed_users, "jane.doe@example.org")
    print(f"Result: {result1}")
    print(f"Database state: {subscribed_users}")

    # Test Case 2: Try to unsubscribe the same user again
    print("\nTest 2: Unsubscribing the same user again...")
    result2 = unsubscribe(subscribed_users, "jane.doe@example.org")
    print(f"Result: {result2}")
    print(f"Database state: {subscribed_users}")

    # Test Case 3: Try to unsubscribe a user not in the database
    print("\nTest 3: Unsubscribing a non-existent user...")
    result3 = unsubscribe(subscribed_users, "not.found@example.com")
    print(f"Result: {result3}")
    print(f"Database state: {subscribed_users}")

    # Test Case 4: Try to unsubscribe with an invalid email format
    print("\nTest 4: Unsubscribing with an invalid email...")
    result4 = unsubscribe(subscribed_users, "invalid-email")
    print(f"Result: {result4}")
    print(f"Database state: {subscribed_users}")
    
    # Test Case 5: Try to unsubscribe with a non-string input (like None)
    print("\nTest 5: Unsubscribing with a None email...")
    result5 = unsubscribe(subscribed_users, None)
    print(f"Result: {result5}")
    print(f"Database state: {subscribed_users}")

if __name__ == "__main__":
    main()