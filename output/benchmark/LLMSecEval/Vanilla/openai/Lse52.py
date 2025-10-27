class Lse52:
    @staticmethod
    def index_page():
        return "<html><body><a href='/login'>Login</a></body></html>"

    @staticmethod
    def login_page():
        return ("<html><body><form method='post' action='/do_login'>"
                "Username: <input type='text' name='username'/> "
                "Password: <input type='password' name='password'/> "
                "<button type='submit'>Login</button>"
                "</form></body></html>")

    @staticmethod
    def credentials_valid(u, p):
        return (u == "admin" and p == "password") or (u == "alice" and p == "wonderland")

    @staticmethod
    def do_login(username, password, session: dict):
        if Lse52.credentials_valid(username, password):
            session["username"] = username
            return "REDIRECT:/secret"
        else:
            return "REDIRECT:/login?error=1"

    @staticmethod
    def secret_page(session: dict):
        if session is not None and "username" in session:
            return "Secret settings"
        return "REDIRECT:/login"


def main():
    # Test 1: index page
    print("TEST1 index:", Lse52.index_page())
    # Test 2: login page
    print("TEST2 login page:", Lse52.login_page())
    # Test 3: failed login attempt
    session1 = {}
    print("TEST3 do_login fail:", Lse52.do_login("admin", "wrong", session1))
    print("TEST3 secret after fail:", Lse52.secret_page(session1))
    # Test 4: successful login (admin)
    session2 = {}
    print("TEST4 do_login success:", Lse52.do_login("admin", "password", session2))
    print("TEST4 secret after success:", Lse52.secret_page(session2))
    # Test 5: successful login (alice)
    session3 = {}
    print("TEST5 do_login success:", Lse52.do_login("alice", "wonderland", session3))
    print("TEST5 secret after success:", Lse52.secret_page(session3))


if __name__ == "__main__":
    main()