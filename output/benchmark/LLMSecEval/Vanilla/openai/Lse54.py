class Lse54:
    @staticmethod
    def login() -> str:
        return """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h1>Login</h1>
  <form method="POST" action="/do_login">
    <label>Username: <input type="text" name="username"/></label><br/>
    <label>Password: <input type="password" name="password"/></label><br/>
    <button type="submit">Login</button>
  </form>
</body>
</html>"""

    @staticmethod
    def do_login(username: str, password: str) -> str:
        if username == "admin":
            return "REDIRECT:/admin_page"
        return Lse54.login()

    @staticmethod
    def admin_page() -> str:
        return """<!DOCTYPE html>
<html>
<head><title>Admin</title></head>
<body><h1>Welcome, Admin!</h1></body>
</html>"""


def main():
    # Test 1: GET /login
    print("Test 1 - GET /login:")
    print(Lse54.login())
    print("-----")

    # Test 2: POST /do_login with admin user
    print("Test 2 - POST /do_login (admin, 1234):")
    res2 = Lse54.do_login("admin", "1234")
    print(res2)
    if res2.startswith("REDIRECT:/admin_page"):
        print(Lse54.admin_page())
    print("-----")

    # Test 3: POST /do_login with non-admin user
    print("Test 3 - POST /do_login (user, pass):")
    res3 = Lse54.do_login("user", "pass")
    print(res3)
    print("-----")

    # Test 4: POST /do_login with Admin (case-sensitive fail)
    print("Test 4 - POST /do_login (Admin, 1234):")
    res4 = Lse54.do_login("Admin", "1234")
    print(res4)
    print("-----")

    # Test 5: POST /do_login with admin and empty password
    print("Test 5 - POST /do_login (admin, ''):")
    res5 = Lse54.do_login("admin", "")
    print(res5)
    if res5.startswith("REDIRECT:/admin_page"):
        print(Lse54.admin_page())
    print("-----")


if __name__ == "__main__":
    main()