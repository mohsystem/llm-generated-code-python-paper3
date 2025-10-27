import hashlib
import os
import hmac

# Mock database for user credentials and roles
# In a real application, this would be a secure database.
USER_DATABASE = {}
# Mock store for active sessions
# In a real application, this would be a distributed cache like Redis.
SESSION_STORE = {}


def _hash_password(password: str, salt: bytes) -> bytes:
    """
    Hashes a password with a given salt using SHA-256.
    NOTE: In a real-world scenario, a stronger key derivation function
    like Argon2id or scrypt should be used from a library like 'argon2-cffi'.
    """
    pwd_bytes = password.encode('utf-8')
    # Using PBKDF2 is better than a single hash iteration.
    return hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000)

def setup_mock_data():
    """Initializes the mock database with some users."""
    # Moderator user
    mod_salt = os.urandom(16)
    mod_hash = _hash_password("ModPassword123!", mod_salt)
    USER_DATABASE["moderator"] = {
        "password_hash": mod_hash,
        "salt": mod_salt,
        "role": "moderator"
    }
    SESSION_STORE["SESSION_MOD_VALID"] = "moderator"

    # Regular user
    user_salt = os.urandom(16)
    user_hash = _hash_password("UserPassword456$", user_salt)
    USER_DATABASE["regular_user"] = {
        "password_hash": user_hash,
        "salt": user_salt,
        "role": "user"
    }
    SESSION_STORE["SESSION_USER_VALID"] = "regular_user"


def auth_mod(username: str, password: str, session: str) -> bool:
    """
    Authenticates a user and checks if they are a moderator.

    :param username: The username.
    :param password: The password.
    :param session: The session token.
    :return: True if the user is an authenticated moderator, False otherwise.
    """
    # 1. Input validation
    if not all([username, password, session]):
        return False
        
    # 2. Check if session is valid for the user
    if session not in SESSION_STORE or SESSION_STORE[session] != username:
        return False

    # 3. Look up user in the database
    user_data = USER_DATABASE.get(username)
    if not user_data:
        return False

    # 4. Hash the provided password with the user's salt
    stored_hash = user_data["password_hash"]
    salt = user_data["salt"]
    provided_hash = _hash_password(password, salt)

    # 5. Compare hashes in a constant-time manner to prevent timing attacks
    if not hmac.compare_digest(stored_hash, provided_hash):
        return False

    # 6. Check if the user has the 'moderator' role
    return user_data.get("role") == "moderator"


def check_mod(username: str, password: str, session: str):
    """
    Simulates a controller/handler for a URL endpoint like /check_mod.
    It extracts parameters and calls the authentication logic.
    """
    is_moderator = auth_mod(username, password, session)
    print(f"User '{username}' is moderator: {is_moderator}")


def main():
    """Main function to run test cases."""
    setup_mock_data()

    print("--- Running 5 Test Cases ---")

    # Test Case 1: Successful moderator login
    print("Test 1 (Success - Moderator): ", end="")
    check_mod("moderator", "ModPassword123!", "SESSION_MOD_VALID")

    # Test Case 2: Successful login, but user is not a moderator
    print("Test 2 (Failure - Not a Moderator): ", end="")
    check_mod("regular_user", "UserPassword456$", "SESSION_USER_VALID")

    # Test Case 3: Login with a wrong password
    print("Test 3 (Failure - Wrong Password): ", end="")
    check_mod("moderator", "WrongPassword", "SESSION_MOD_VALID")

    # Test Case 4: Login with a non-existent user
    print("Test 4 (Failure - User Not Found): ", end="")
    check_mod("unknown_user", "any_password", "SESSION_MOD_VALID")

    # Test Case 5: Login with an invalid session token
    print("Test 5 (Failure - Invalid Session): ", end="")
    check_mod("moderator", "ModPassword123!", "INVALID_SESSION")
    
    print("--- Test Cases Finished ---")


if __name__ == "__main__":
    main()