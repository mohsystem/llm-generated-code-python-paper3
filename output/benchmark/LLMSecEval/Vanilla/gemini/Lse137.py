def auth_mod(username, password, session):
    """
    Checks if a user is a moderator based on hardcoded credentials.
    In a real application, this would involve database lookups, password hashing,
    and proper session validation.
    The session parameter is included to match requirements but is not used.
    """
    # Simple hardcoded check for demonstration
    return username == "admin" and password == "admin_pass"

def check_mod(username, password, session):
    """
    Simulates a URL endpoint that checks for moderator privileges.
    It receives user credentials and calls the authentication logic.
    """
    return auth_mod(username, password, session)

if __name__ == "__main__":
    # 5 test cases
    print("--- Test Cases ---")

    # Test Case 1: Correct moderator credentials
    is_mod1 = check_mod("admin", "admin_pass", "sess_abc123")
    print(f"Test 1 (admin, admin_pass): Is Moderator? {is_mod1}")

    # Test Case 2: Incorrect password
    is_mod2 = check_mod("admin", "wrong_pass", "sess_def456")
    print(f"Test 2 (admin, wrong_pass): Is Moderator? {is_mod2}")

    # Test Case 3: Incorrect username
    is_mod3 = check_mod("user", "admin_pass", "sess_ghi789")
    print(f"Test 3 (user, admin_pass): Is Moderator? {is_mod3}")

    # Test Case 4: Regular user credentials
    is_mod4 = check_mod("user", "user_pass", "sess_jkl012")
    print(f"Test 4 (user, user_pass): Is Moderator? {is_mod4}")

    # Test Case 5: Empty credentials
    is_mod5 = check_mod("", "", "sess_mno345")
    print(f"Test 5 (empty credentials): Is Moderator? {is_mod5}")