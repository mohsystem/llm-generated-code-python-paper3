import re
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
HOST_RE = re.compile(r'^([^.]+\.)*example\.com$', re.IGNORECASE)

def safe_redirect(target: str) -> str:
    if target is None:
        return "/"
    t = target.strip()
    if not t or len(t) > MAX_URL_LENGTH:
        return "/"
    if "\r" in t or "\n" in t:
        return "/"

    parts = urlsplit(t)
    if parts.scheme.lower() not in ("http", "https"):
        return "/"
    if not parts.hostname:
        return "/"

    try:
        ascii_host = parts.hostname.encode("idna").decode("ascii")
    except Exception:
        return "/"

    if not HOST_RE.match(ascii_host):
        return "/"

    return t

if __name__ == "__main__":
    tests = [
        "https://example.com/abc",
        "http://sub.example.com:8080/path",
        "https://evil.com",
        "/relative/path",
        "https://notexample.com",
    ]
    for test in tests:
        print(f"Input: {test} -> Redirect: {safe_redirect(test)}")