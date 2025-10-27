import re
import threading

# In a real application, this would be a persistent database.
# Using a set for efficient lookups and a lock for thread-safety.
database = {"test@example.com", "user1@domain.com", "another.user@service.net"}
db_lock = threading.Lock()

# A simple regex for email validation.
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$")
MAX_EMAIL_LENGTH = 254

def unsubscribe(email: str) -> str:
    """
    Unsubscribes a user by removing their email from the database.

    Args:
        email: The email address of the user to unsubscribe.

    Returns:
        A string message indicating the result of the operation.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(email, str) or not email:
        return "Error: Email parameter cannot be empty."
    if len(email) > MAX_EMAIL_LENGTH:
        return "Error: Email address is too long."
    if not EMAIL_REGEX.match(email):
        return "Error: Invalid email format."

    # Use a lock to ensure thread-safe access to the shared database
    with db_lock:
        if email in database:
            database.remove(email)
            # In a real application, you would also perform other actions,
            # e.g., unsubscribing from a third-party mailing list service.
            return "User unsubscribed successfully."
        else:
            return "User is not subscribed."

def main():
    """ Main function with 5 test cases. """
    print(f"Initial database state: {database}")
    print("--- Running 5 Test Cases ---")

    # Test Case 1: A valid email that exists in the database.
    email1 = "test@example.com"
    print(f"\n1. Unsubscribing '{email1}':")
    result1 = unsubscribe(email1)
    print(f"   Result: {result1}")
    print(f"   Database state: {database}")

    # Test Case 2: The same email, which should now be gone.
    print(f"\n2. Unsubscribing '{email1}' again:")
    result2 = unsubscribe(email1)
    print(f"   Result: {result2}")

    # Test Case 3: A valid email that is not in the database.
    email3 = "notfound@example.com"
    print(f"\n3. Unsubscribing '{email3}':")
    result3 = unsubscribe(email3)
    print(f"   Result: {result3}")

    # Test Case 4: An invalid email format.
    email4 = "invalid-email"
    print(f"\n4. Unsubscribing '{email4}':")
    result4 = unsubscribe(email4)
    print(f"   Result: {result4}")

    # Test Case 5: A None (null) email input.
    email5 = None
    print("\n5. Unsubscribing a None email:")
    # The type hint expects a string, but we test None to be robust
    result5 = unsubscribe(email5)
    print(f"   Result: {result5}")
    
    print("\n--- Test Cases Complete ---")
    print(f"Final database state: {database}")


if __name__ == "__main__":
    main()