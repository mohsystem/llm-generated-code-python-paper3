def get_redirect_page(is_logged_in: bool, is_admin: bool) -> str:
    """
    Determines the redirection page based on user's login and admin status.

    Args:
        is_logged_in: A boolean indicating if the user is logged in.
        is_admin: A boolean indicating if the logged-in user is an admin.

    Returns:
        A string representing the page to redirect to.
    """
    if is_logged_in:
        if is_admin:
            return "admin page"
        else:
            return "user page"
    else:
        return "login page"

if __name__ == "__main__":
    # Test cases
    print(f"Test Case 1: (Logged In: False, Is Admin: False) -> {get_redirect_page(False, False)}")
    print(f"Test Case 2: (Logged In: False, Is Admin: True) -> {get_redirect_page(False, True)}")
    print(f"Test Case 3: (Logged In: True, Is Admin: False) -> {get_redirect_page(True, False)}")
    print(f"Test Case 4: (Logged In: True, Is Admin: True) -> {get_redirect_page(True, True)}")
    print(f"Test Case 5: (Another not logged in) -> {get_redirect_page(False, False)}")