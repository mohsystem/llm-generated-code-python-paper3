
def redirect_user(is_logged_in, is_admin):
    """\n    Determines which page to redirect the user to based on login status and admin rights.\n    \n    Args:\n        is_logged_in (bool): Whether the user is logged in\n        is_admin (bool): Whether the user is an admin\n    \n    Returns:\n        str: The page to redirect to\n    """
    if not is_logged_in:
        return "login.html"
    elif is_admin:
        return "admin.html"
    else:
        return "user.html"


def handle_redirect(session):
    """\n    Handles redirect based on session information.\n    \n    Args:\n        session (dict): Session dictionary containing user information\n    \n    Returns:\n        str: The page to redirect to\n    """
    is_logged_in = session.get('is_logged_in', False)
    is_admin = session.get('is_admin', False)
    
    return redirect_user(is_logged_in, is_admin)


class Lse53:
    @staticmethod
    def redirect_user(is_logged_in, is_admin):
        return redirect_user(is_logged_in, is_admin)
    
    @staticmethod
    def handle_redirect(session):
        return handle_redirect(session)


if __name__ == "__main__":
    # Test case 1: User not logged in
    print("Test 1 - Not logged in:", redirect_user(False, False))
    
    # Test case 2: User logged in but not admin
    print("Test 2 - Logged in, not admin:", redirect_user(True, False))
    
    # Test case 3: User logged in and is admin
    print("Test 3 - Logged in, is admin:", redirect_user(True, True))
    
    # Test case 4: Not logged in but somehow admin flag is true
    print("Test 4 - Not logged in, admin flag true:", redirect_user(False, True))
    
    # Test case 5: Regular user scenario
    print("Test 5 - Regular user:", redirect_user(True, False))
