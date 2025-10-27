# Step 1-5 applied: simple, safe, deterministic function.

def decide_redirect(is_logged_in: bool, is_admin: bool) -> str:
    if not is_logged_in:
        return "/login"
    return "/admin" if is_admin else "/user"


if __name__ == "__main__":
    # 5 test cases
    tests = [
        (False, False),  # /login
        (False, True),   # /login
        (True, False),   # /user
        (True, True),    # /admin
        (True, False),   # /user
    ]
    for i, (li, ad) in enumerate(tests, 1):
        print(f"Test {i} ({li}, {ad}): {decide_redirect(li, ad)}")