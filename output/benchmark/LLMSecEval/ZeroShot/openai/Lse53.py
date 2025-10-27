def secure_redirect(is_logged_in, is_admin):
    if not isinstance(is_logged_in, bool) or not isinstance(is_admin, bool):
        return "/login"
    if not is_logged_in:
        return "/login"
    return "/admin" if is_admin else "/user"


if __name__ == "__main__":
    tests = [
        (False, False),  # /login
        (True, False),   # /user
        (True, True),    # /admin
        (False, True),   # /login
        ("yes", True),   # /login (invalid input)
    ]
    for t in tests:
        print(secure_redirect(*t))