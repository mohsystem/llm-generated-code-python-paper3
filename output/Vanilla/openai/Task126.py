def redirect(user_input: str) -> str:
    if user_input is None:
        return "/home"
    key = user_input.strip().lower()
    if not key:
        return "/home"

    if key.startswith("profile"):
        return "/user/profile"

    routes = {
        "home": "/home",
        "login": "/auth/login",
        "logout": "/auth/logout",
        "admin": "/admin/dashboard",
        "help": "/support/help",
        "settings": "/user/settings",
    }
    return routes.get(key, "/error/404")


if __name__ == "__main__":
    tests = [
        "home",
        "LOGIN",
        "Admin ",
        "profile?id=42",
        "unknown",
    ]
    for t in tests:
        print(f"{t} -> {redirect(t)}")