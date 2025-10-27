import re
from html import escape

# Simple routing registry using a decorator
_ROUTES = []

def route(pattern: str):
    # Convert "/hello/<username>" -> r"^/hello/([^/]+)$"
    regex = re.escape(pattern).replace(r"\<username\>", r"([^/]+)")
    compiled = re.compile(r"^" + regex + r"$")

    def decorator(func):
        _ROUTES.append((compiled, func))
        return func
    return decorator

def navigate(url: str):
    if not isinstance(url, str):
        return None
    for regex, func in _ROUTES:
        m = regex.match(url)
        if m:
            # Only one parameter expected
            username = m.group(1)
            return func(username)
    return None

@route("/hello/<username>")
def hello(username: str) -> str:
    return "Hello " + escape(username, quote=True)

if __name__ == "__main__":
    tests = [
        "/hello/World",
        "/hello/<script>alert(1)</script>",
        "/hello/O'Connor & Sons",
        "/hello/Tom \"T\"",
        "/hello/../path?x=1&y=2"
    ]
    for t in tests:
        print(navigate(t) or "404 Not Found")