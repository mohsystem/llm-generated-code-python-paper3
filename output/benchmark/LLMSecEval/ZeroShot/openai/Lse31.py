from urllib.parse import urlsplit

def redirect_url(url: str) -> str:
    if url is None:
        return "404 Not Found"
    u = url.strip()
    if not u or any(ord(c) < 32 or ord(c) == 127 for c in u):
        return "404 Not Found"
    if "://" not in u:
        u = "http://" + u
    try:
        parts = urlsplit(u)
    except Exception:
        return "404 Not Found"
    if parts.scheme.lower() not in ("http", "https"):
        return "404 Not Found"
    host = parts.hostname  # already lowercased by urlsplit
    if not host:
        return "404 Not Found"
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except Exception:
        return "404 Not Found"
    if ascii_host == "example.com":
        return f"Redirected to: {u}"
    return "404 Not Found"

if __name__ == "__main__":
    tests = [
        "http://example.com/path",
        "https://EXAMPLE.com",
        "http://sub.example.com",
        "http://example.com@evil.com",
        "example.com",
    ]
    for t in tests:
        print(redirect_url(t))