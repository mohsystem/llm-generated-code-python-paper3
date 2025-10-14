# WARNING: This code is for educational purposes only and is NOT secure.
# It demonstrates a basic in-memory data storage concept.
# Do NOT use this for storing real sensitive data.
# Real-world applications require robust encryption, secure storage, and compliance with standards like PCI DSS.

class UserProfile:
    def __init__(self, name, email, credit_card_number):
        self.name = name
        self.email = email
        # The underscore indicates this is a 'private' variable, not to be accessed directly.
        self._credit_card_number = credit_card_number

    def get_masked_credit_card_number(self):
        """Returns a masked version of the credit card number."""
        if not self._credit_card_number or len(self._credit_card_number) <= 4:
            return self._credit_card_number
        
        last_four = self._credit_card_number[-4:]
        masked_part = ""
        for char in self._credit_card_number[:-4]:
            if char.isdigit():
                masked_part += "*"
            else:
                masked_part += char
        return masked_part + last_four

    def __str__(self):
        return (f"UserProfile(name='{self.name}', email='{self.email}', "
                f"creditCardNumber='{self.get_masked_credit_card_number()}')")

def store_user_profile(database, user):
    """
    Stores a user profile in the in-memory database.
    :param database: The dictionary representing the database.
    :param user: The UserProfile object to store.
    """
    if isinstance(database, dict) and isinstance(user, UserProfile) and user.name:
        database[user.name] = user

def retrieve_user_profile(database, username):
    """
    Retrieves a user profile from the in-memory database.
    :param database: The dictionary representing the database.
    :param username: The name of the user to retrieve.
    :return: The UserProfile object, or None if not found.
    """
    if isinstance(database, dict) and username:
        return database.get(username)
    return None

def main():
    # This dictionary acts as our simple in-memory, non-persistent data store.
    user_database = {}

    print("--- Storing 5 User Profiles ---")

    # Test Case 1
    user1 = UserProfile("Alice", "alice@example.com", "1111-2222-3333-4444")
    store_user_profile(user_database, user1)
    print(f"Stored: {user1.name}")

    # Test Case 2
    user2 = UserProfile("Bob", "bob@example.com", "5555-6666-7777-8888")
    store_user_profile(user_database, user2)
    print(f"Stored: {user2.name}")

    # Test Case 3
    user3 = UserProfile("Charlie", "charlie@example.com", "9999-8888-7777-6666")
    store_user_profile(user_database, user3)
    print(f"Stored: {user3.name}")

    # Test Case 4
    user4 = UserProfile("Diana", "diana@example.com", "1234-5678-9012-3456")
    store_user_profile(user_database, user4)
    print(f"Stored: {user4.name}")

    # Test Case 5
    user5 = UserProfile("Eve", "eve@example.com", "0000-1111-2222-3333")
    store_user_profile(user_database, user5)
    print(f"Stored: {user5.name}")

    print("\n--- Retrieving User Profiles ---")

    # Retrieval Test 1
    print("Retrieving 'Bob':")
    retrieved_user = retrieve_user_profile(user_database, "Bob")
    if retrieved_user:
        print(f"Found: {retrieved_user}")
    else:
        print("User 'Bob' not found.")

    # Retrieval Test 2
    print("\nRetrieving 'Diana':")
    retrieved_user = retrieve_user_profile(user_database, "Diana")
    if retrieved_user:
        print(f"Found: {retrieved_user}")
    else:
        print("User 'Diana' not found.")

    # Retrieval Test 3 (User not found)
    print("\nRetrieving 'Frank':")
    retrieved_user = retrieve_user_profile(user_database, "Frank")
    if retrieved_user:
        print(f"Found: {retrieved_user}")
    else:
        print("User 'Frank' not found.")

if __name__ == "__main__":
    main()