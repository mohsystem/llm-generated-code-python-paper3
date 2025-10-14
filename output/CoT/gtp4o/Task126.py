# Step 1: Problem understanding: route users to pages based on input
# Step 2: Security: enforce whitelist, validate/sanitize input, avoid open redirects
# Step 3: Secure coding: strict regex validation and dictionary lookup
# Step 4: Code review: no dynamic URL construction, no external calls
# Step 5: Secure output: only known routes or /error

import re

_ROUTES = {
    "home": "/home",
    "profile": "/user/profile",
    "settings": "/settings",
    "help": "/help",
    "logout": "/logout",
}

def _sanitize(user_input: str) -> str:
    if user_input is None:
        return ""
    s = str(user_input).strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]+", s):
        return ""
    return s

def get_redirect_target(user_input: str) -> str:
    key = _sanitize(user_input)
    return _ROUTES.get(key, "/error")

if __name__ == "__main__":
    tests = ["home", "HoMe", " profile ", "../admin", "unknown"]
    for t in tests:
        print(f'Input: "{t}" -> Redirect: {get_redirect_target(t)}')