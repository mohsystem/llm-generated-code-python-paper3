def redirect_user(is_logged_in, is_admin):
    """
    Determines the redirection page based on user's login and admin status.

    Args:
        is_logged_in (bool): A boolean indicating if the user is logged in.
        is_admin (bool): A boolean indicating if the logged-in user is an admin.

    Returns:
        str: A string message indicating the redirection destination.
    """
    if not is_logged_in:
        return "Redirecting to Login Page"
    elif is_admin:
        return "Redirecting to Admin Page"
    else:
        return "Redirecting to User Page"

if __name__ == "__main__":
    # Test Case 1: Not logged in
    print(f"Test Case 1 (is_logged_in: False, is_admin: False): {redirect_user(False, False)}")

    # Test Case 2: Not logged in, but admin flag is true (should still go to login)
    print(f"Test Case 2 (is_logged_in: False, is_admin: True): {redirect_user(False, True)}")

    # Test Case 3: Logged in, but not an admin
    print(f"Test Case 3 (is_logged_in: True, is_admin: False): {redirect_user(True, False)}")

    # Test Case 4: Logged in and is an admin
    print(f"Test Case 4 (is_logged_in: True, is_admin: True): {redirect_user(True, True)}")
    
    # Test Case 5: Another test for a regular logged-in user
    print(f"Test Case 5 (is_logged_in: True, is_admin: False): {redirect_user(True, False)}")