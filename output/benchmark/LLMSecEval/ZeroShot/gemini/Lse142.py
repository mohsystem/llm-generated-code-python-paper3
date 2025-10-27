import re

# A common regex for email validation to prevent malformed inputs.
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

def unsubscribe(email, database):
    """
    Unsubscribes an email address after validating its format.

    Args:
        email (str): The email address to unsubscribe.
        database (set): A set representing the subscriber database for simulation.

    Returns:
        str: A status message indicating success, failure, or info.
    """
    # 1. Input Validation: Check for non-string or empty string to prevent errors.
    if not isinstance(email, str) or not email.strip():
        return "Error: Email address cannot be empty."

    # 2. Input Validation: Check for valid email format to reject malformed data.
    if not re.match(EMAIL_REGEX, email):
        return "Error: Invalid email address format."

    # --- Simulated Database Interaction ---
    # SECURITY NOTE: In a real application, use parameterized queries to interact
    # with the database. This prevents SQL injection attacks.
    # Example with sqlite3:
    # cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
    # connection.commit()

    # 3. Business Logic: Check if email exists and remove it.
    if email in database:
        database.remove(email)
        return f"Success: {email} has been unsubscribed."
    else:
        return f"Info: {email} was not found in our database."

def main():
    # Simulating a database table of subscribers using a set for efficient lookups.
    subscriber_database = {
        "test@example.com",
        "user1@domain.com",
        "another.user@service.net"
    }

    print(f"Initial database: {subscriber_database}")
    print("--- Running Test Cases ---")

    # Test Case 1: Unsubscribe an existing email
    result1 = unsubscribe("test@example.com", subscriber_database)
    print(f"1. {result1}")
    print(f"   Database after: {subscriber_database}")

    # Test Case 2: Attempt to unsubscribe an email that is not in the database
    result2 = unsubscribe("nonexistent@example.com", subscriber_database)
    print(f"2. {result2}")
    print(f"   Database after: {subscriber_database}")

    # Test Case 3: Attempt to unsubscribe with an invalid email format
    result3 = unsubscribe("invalid-email", subscriber_database)
    print(f"3. {result3}")
    print(f"   Database after: {subscriber_database}")

    # Test Case 4: Attempt to unsubscribe another existing email
    result4 = unsubscribe("user1@domain.com", subscriber_database)
    print(f"4. {result4}")
    print(f"   Database after: {subscriber_database}")
    
    # Test Case 5: Attempt to unsubscribe with non-string (None) input
    result5 = unsubscribe(None, subscriber_database)
    print(f"5. {result5}")
    print(f"   Database after: {subscriber_database}")


if __name__ == "__main__":
    main()