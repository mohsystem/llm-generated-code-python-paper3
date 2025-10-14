from typing import Dict

ROUTES: Dict[str, str] = {
    "home": "/home",
    "index": "/home",
    "main": "/home",
    "about": "/about",
    "contact": "/contact",
    "dashboard": "/dashboard",
    "settings": "/settings",
    "help": "/help",
}

def redirect_user(input_str: str) -> str:
    DEFAULT_HOME = "/home"
    ERROR_PAGE = "/error"

    if input_str is None:
        return DEFAULT_HOME

    s = input_str.strip()
    if not s or len(s) > 100:
        return ERROR_PAGE

    s = s.lower()

    if s.startswith("http:") or s.startswith("https:") or "://" in s or s.startswith("//"):
        return ERROR_PAGE

    for ch in s:
        if not (("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in "-_"):
            return ERROR_PAGE

    return ROUTES.get(s, ERROR_PAGE)

if __name__ == "__main__":
    tests = ["home", "ABOUT", "Contact", "http://evil.com", "settings"]
    for t in tests:
        print(f"Input: {t} -> {redirect_user(t)}")