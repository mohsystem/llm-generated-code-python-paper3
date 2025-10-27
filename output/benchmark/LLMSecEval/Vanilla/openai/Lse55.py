def login(query: str) -> str:
    # GET /login
    return f"GET /login -> provide credentials via POST to /do_login. Query={'' if query is None else query}"

def do_login(username: str, password: str) -> str:
    # POST /do_login
    if username == "admin" and password == "secret":
        return "admin|admin"
    elif username == "user" and password == "pass":
        return "user|user"
    else:
        return "ERROR: Invalid credentials"

def index(session_token: str) -> str:
    # GET /
    if not session_token or session_token.startswith("ERROR"):
        return "Welcome, Guest"
    parts = session_token.split("|", 1)
    user = parts[0] if parts else "Guest"
    return f"Welcome, {user}"

def user_page(session_token: str) -> str:
    # GET /user
    if not session_token or session_token.startswith("ERROR"):
        return "401 Unauthorized"
    parts = session_token.split("|", 1)
    if len(parts) < 2:
        return "401 Unauthorized"
    user, role = parts[0], parts[1]
    if role in ("user", "admin"):
        return f"User Page for {user}"
    return "401 Unauthorized"

def admin_page(session_token: str) -> str:
    # GET /admin
    if not session_token or session_token.startswith("ERROR"):
        return "401 Unauthorized"
    parts = session_token.split("|", 1)
    if len(parts) < 2:
        return "401 Unauthorized"
    user, role = parts[0], parts[1]
    if role == "admin":
        return f"Admin Page for {user}"
    return "401 Unauthorized"

if __name__ == "__main__":
    # 5 test cases
    print("Test 1:", login("next=/home"))
    token_user = do_login("user", "pass")
    print("Test 2:", index(token_user))
    print("Test 3:", user_page(token_user))
    print("Test 4:", admin_page(token_user))
    token_admin = do_login("admin", "secret")
    print("Test 5:", admin_page(token_admin))