import hmac

def login():
    # Return HTML form for GET /login
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Login</title></head>'
        '<body><form method="POST" action="/do_login">'
        '<label>Username: <input type="text" name="username" required></label><br>'
        '<label>Password: <input type="password" name="password" required></label><br>'
        '<button type="submit">Login</button>'
        '</form></body></html>'
    )

def do_login(username: str, password: str) -> str:
    if username is None:
        username = ""
    # Constant-time compare against "admin"
    if hmac.compare_digest(username.encode("utf-8"), b"admin"):
        return "REDIRECT:/admin_page"
    return ""

if __name__ == "__main__":
    print("GET /login ->")
    print(login())
    print()

    # 5 test cases
    print("POST /do_login admin/adminpass ->", do_login("admin", "adminpass"))
    print("POST /do_login admin/wrong ->", do_login("admin", "wrong"))
    print("POST /do_login user/adminpass ->", do_login("user", "adminpass"))
    print("POST /do_login empty/empty ->", do_login("", ""))
    print("POST /do_login Admin(case)/pass ->", do_login("Admin", "pass"))