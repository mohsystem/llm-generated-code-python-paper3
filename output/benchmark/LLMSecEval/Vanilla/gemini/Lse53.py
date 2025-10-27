def redirect_user(is_logged_in, is_admin):
    """
    Determines the redirection page based on user's login and admin status.

    :param is_logged_in: A boolean indicating if the user is logged in.
    :param is_admin: A boolean indicating if the logged-in user is an admin.
    :return: A string representing the page to redirect to.
    """
    if is_logged_in:
        if is_admin:
            return "Admin Page"
        else:
            return "User Page"
    else:
        return "Login Page"

def main():
    # Test Cases
    print(f"Test Case 1 (Not logged in, not admin): {redirect_user(False, False)}")
    print(f"Test Case 2 (Not logged in, is admin): {redirect_user(False, True)}")
    print(f"Test Case 3 (Logged in, not admin): {redirect_user(True, False)}")
    print(f"Test Case 4 (Logged in, is admin): {redirect_user(True, True)}")
    print(f"Test Case 5 (Another logged in user): {redirect_user(True, False)}")

if __name__ == "__main__":
    main()