from typing import Optional, Dict

ROUTES: Dict[str, str] = {
    "home": "/home",
    "about": "/about",
    "contact": "/contact",
    "help": "/help",
    "dashboard": "/user/dashboard",
}

def _is_safe_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if not (1 <= len(username) <= 30):
        return False
    for ch in username:
        if not (ch.isalnum() or ch == "_"):
            return False
    return True

def resolve_redirect(user_input: Optional[str]) -> str:
    if user_input is None:
        return "/error?code=bad-request"
    s = user_input.strip()
    if not s:
        return "/error?code=bad-request"
    if len(s) > 100:
        return "/error?code=too-long"

    if ":" in s:
        head, tail = s.split(":", 1)
        head = head.strip().lower()
        tail = tail.strip()
        if head == "profile":
            if not _is_safe_username(tail):
                return "/error?code=invalid-username"
            return f"/user/profile/{tail}"
        return "/error?code=unknown-page"
    else:
        key = s.lower()
        return ROUTES.get(key, "/error?code=unknown-page")

if __name__ == "__main__":
    tests = [
        "home",
        "Profile:Alice_123",
        "profile:bad/../hacker",
        "unknown",
        "dashboard",
    ]
    for t in tests:
        print(f"Input: {t} -> Redirect: {resolve_redirect(t)}")