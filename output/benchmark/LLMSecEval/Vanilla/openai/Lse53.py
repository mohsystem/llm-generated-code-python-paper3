def get_redirect(is_logged_in: bool, is_admin: bool) -> str:
    if not is_logged_in:
        return "login"
    if is_admin:
        return "admin"
    return "user"

if __name__ == "__main__":
    print(get_redirect(False, False))  # Expected: login
    print(get_redirect(False, True))   # Expected: login
    print(get_redirect(True, False))   # Expected: user
    print(get_redirect(True, True))    # Expected: admin
    print(get_redirect(True, False))   # Expected: user