def get_redirect_page(is_logged_in, is_admin):
    """
    Determines the redirection page based on user's login status and admin role.
    This implementation is secure because it checks for login status first.
    An admin role is only considered if the user is already authenticated.
    It defaults to the most restrictive page (login) if not authenticated.
    
    Args:
        is_logged_in (bool): A boolean indicating if the user is logged in.
        is_admin (bool): A boolean indicating if the logged-in user is an admin.
    
    Returns:
        str: A string representing the page to redirect to.
    """
    if is_logged_in:
        if is_admin:
            return "/admin"  # User is logged in and is an admin
        else:
            return "/user"  # User is logged in but is not an admin
    else:
        return "/login"  # User is not logged in

def main():
    """ Main function with test cases """
    print("--- Python Test Cases ---")
    
    # Test Case 1: User is not logged in.
    is_logged_in1, is_admin1 = False, False
    print(f"Test Case 1 (Logged In: {is_logged_in1}, Is Admin: {is_admin1}): {get_redirect_page(is_logged_in1, is_admin1)}")

    # Test Case 2: Logged in as a regular user.
    is_logged_in2, is_admin2 = True, False
    print(f"Test Case 2 (Logged In: {is_logged_in2}, Is Admin: {is_admin2}): {get_redirect_page(is_logged_in2, is_admin2)}")

    # Test Case 3: Logged in as an admin.
    is_logged_in3, is_admin3 = True, True
    print(f"Test Case 3 (Logged In: {is_logged_in3}, Is Admin: {is_admin3}): {get_redirect_page(is_logged_in3, is_admin3)}")

    # Test Case 4: Not logged in, but admin flag is true (invalid state). Should redirect to login.
    is_logged_in4, is_admin4 = False, True
    print(f"Test Case 4 (Logged In: {is_logged_in4}, Is Admin: {is_admin4}): {get_redirect_page(is_logged_in4, is_admin4)}")

    # Test Case 5: Another regular logged-in user.
    is_logged_in5, is_admin5 = True, False
    print(f"Test Case 5 (Logged In: {is_logged_in5}, Is Admin: {is_admin5}): {get_redirect_page(is_logged_in5, is_admin5)}")

if __name__ == "__main__":
    main()