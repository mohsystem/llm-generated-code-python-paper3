import hmac
import html

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "AdminPassword!234"

def login():
    # Return a minimal secure HTML form (no user-controlled data embedded)
    return (
        "<!DOCTYPE html>"
        "<html><head><meta charset=\"utf-8\"><title>Login</title></head>"
        "<body>"
        "<form action=\"/do_login\" method=\"post\" autocomplete=\"off\">"
        "<label for=\"username\">Username:</label>"
        "<input type=\"text\" id=\"username\" name=\"username\" required minlength=\"1\" maxlength=\"64\" />"
        "<label for=\"password\">Password:</label>"
        "<input type=\"password\" id=\"password\" name=\"password\" required minlength=\"1\" maxlength=\"128\" />"
        "<button type=\"submit\">Login</button>"
        "</form>"
        "</body></html>"
    )

def _valid_username(username: str) -> bool:
    if username is None:
        return False
    if not (1 <= len(username) <= 64):
        return False
    for ch in username:
        if not (ch.isalnum() or ch in {'.', '_', '-'}):
            return False
    return True

def _valid_password(password: str) -> bool:
    return password is not None and (1 <= len(password) <= 128)

def do_login(username: str, password: str) -> str:
    if not _valid_username(username) or not _valid_password(password):
        return "400 Bad Request"
    is_admin_user = hmac.compare_digest(username, ADMIN_USERNAME)
    is_admin_pass = hmac.compare_digest(password, ADMIN_PASSWORD)
    if is_admin_user and is_admin_pass:
        return "REDIRECT:/admin_page"
    return "401 Unauthorized"

if __name__ == "__main__":
    # 5 test cases
    print("TEST1 FORM:")
    print(login())
    print("TEST2 ADMIN CORRECT:")
    print(do_login("admin", "AdminPassword!234"))
    print("TEST3 ADMIN WRONG PASS:")
    print(do_login("admin", "wrong"))
    print("TEST4 NON-ADMIN:")
    print(do_login("user", "AdminPassword!234"))
    print("TEST5 BAD INPUT:")
    print(do_login("", ""))