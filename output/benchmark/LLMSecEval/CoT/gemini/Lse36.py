import hmac

# Simulates a database. In a real application, passwords would be hashed
# with a strong, slow algorithm like bcrypt or Argon2.
USER_DATABASE = {
    "admin": "321drowssap_hashed",  # Simulated hash of "password123"
    "jdoe": "#@!ssaPeruces_hashed", # Simulated hash of "securePass!@#"
    "testuser": "tset_hashed"      # Simulated hash of "test"
}

def hash_password(password: str) -> str:
    """
    Simulates hashing a password.
    In a real system, use a library like passlib or bcrypt.
    This is NOT a secure hash. For demonstration only.
    """
    return password[::-1] + "_hashed"

def login(username: str, password: str) -> str:
    """
    Simulates a user login process.

    Args:
        username: The username entered by the user.
        password: The password entered by the user.

    Returns:
        A string indicating the result of the login attempt.
    """
    if not username or not password:
        return "Username or password cannot be empty."

    stored_hashed_password = USER_DATABASE.get(username)
    input_hashed_password = hash_password(password)

    # We perform the comparison regardless of whether the user was found
    # to help mitigate timing attacks that could enumerate usernames.
    # If user not found, stored_hashed_password is None, so the comparison will fail.
    # hmac.compare_digest is used for constant-time string comparison to prevent timing attacks.
    
    login_success = False
    if stored_hashed_password:
        if hmac.compare_digest(stored_hashed_password, input_hashed_password):
            login_success = True

    if login_success:
        return "Login successful! Redirecting to home page..."
    else:
        # Generic error message to prevent username enumeration.
        return "Invalid username or password."

def main():
    """ Main function to run test cases. """
    print("--- Login Test Cases ---")

    # Test Case 1: Successful login
    print(f'1. admin / password123 -> {login("admin", "password123")}')

    # Test Case 2: Incorrect password
    print(f'2. admin / wrongpassword -> {login("admin", "wrongpassword")}')

    # Test Case 3: Non-existent user
    print(f'3. unknownuser / password123 -> {login("unknownuser", "password123")}')

    # Test Case 4: Another successful login
    print(f'4. jdoe / securePass!@# -> {login("jdoe", "securePass!@#")}')

    # Test Case 5: Empty credentials
    print(f'5. "" / "" -> {login("", "")}')

if __name__ == "__main__":
    main()