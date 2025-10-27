from typing import Callable, Dict, Tuple, Optional

# Simple routing mechanism using a decorator-like pattern
_routes: Dict[str, Callable[[str], str]] = {}

MAX_PATH_LEN = 2048
MAX_USERNAME_LEN = 256

def escape_html(s: str) -> str:
    # Minimal HTML escaping
    out = []
    for ch in s:
        if ch == '&':
            out.append("&amp;")
        elif ch == '<':
            out.append("&lt;")
        elif ch == '>':
            out.append("&gt;")
        elif ch == '"':
            out.append("&quot;")
        elif ch == "'":
            out.append("&#x27;")
        else:
            out.append(ch)
    return "".join(out)

def route(pattern: str):
    def decorator(func: Callable[[str], str]) -> Callable[[str], str]:
        _routes[pattern] = func
        return func
    return decorator

def _match_hello(pattern: str, path: str) -> Tuple[bool, Optional[str], Optional[str]]:
    # Returns (matched, username, error)
    if pattern != "/hello/<username>":
        return False, None, None
    if not path.startswith("/hello/"):
        return False, None, None
    username = path[len("/hello/"):]
    if not username or "/" in username:
        return False, None, None
    if len(path.encode("utf-8")) > MAX_PATH_LEN:
        return True, None, "400 Bad Request"
    if len(username.encode("utf-8")) > MAX_USERNAME_LEN:
        return True, None, "400 Bad Request"
    return True, username, None

def handle(path: str) -> str:
    if not isinstance(path, str) or len(path.encode("utf-8")) == 0 or len(path.encode("utf-8")) > MAX_PATH_LEN:
        return "400 Bad Request"
    for pattern, func in _routes.items():
        matched, username, err = _match_hello(pattern, path)
        if not matched:
            continue
        if err:
            return err
        try:
            return func(username)  # type: ignore[arg-type]
        except Exception:
            return "500 Internal Server Error"
    return "404 Not Found"

@route("/hello/<username>")
def hello(username: str) -> str:
    return "Hello " + escape_html(username)

if __name__ == "__main__":
    tests = [
        "/hello/Alice",
        "/hello/Bob<Admin>",
        "/hello/",
        "/hi/Alice",
        "/hello/" + ("A" * 300),
    ]
    for t in tests:
        print(f"URL: {t} -> {handle(t)}")