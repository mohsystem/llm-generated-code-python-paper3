from urllib.parse import urlparse

MAX_URL_LEN = 2048

def redirect_url(url: str) -> str:
    if not isinstance(url, str):
        return "404 Not Found"
    url = url.strip()
    if not url or len(url) > MAX_URL_LEN:
        return "404 Not Found"

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return "404 Not Found"

    netloc = parsed.netloc or ""
    if not netloc:
        return "404 Not Found"

    # Strip userinfo if present
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]

    # Handle IPv6 literals [::1]:port; else separate by ':'
    if netloc.startswith("["):
        end = netloc.find("]")
        if end <= 0:
            return "404 Not Found"
        host = netloc[1:end]
    else:
        host = netloc.split(":", 1)[0]

    if host.lower() == "example.com":
        return "REDIRECT " + url
    return "404 Not Found"


if __name__ == "__main__":
    tests = [
        "https://example.com/path",
        "http://example.com:80?a=b",
        "http://sub.example.com/",
        "ftp://example.com/file",
        "https://evil.com/",
    ]
    for t in tests:
        print(redirect_url(t))