from urllib.parse import urlparse

def redirect_url(url: str) -> int:
    if url is None:
        return 404
    u = url.strip()
    if not u:
        return 404
    if u.startswith("//"):
        parsed = urlparse("http:" + u)
    else:
        parsed = urlparse(u)
    host = parsed.hostname
    if host is None:
        return 404
    if host.lower() == "example.com":
        return 302
    return 404

if __name__ == "__main__":
    tests = [
        "https://example.com/page",
        "http://Example.com",
        "https://sub.example.com/home",
        "//example.com/resource",
        "mailto:user@example.com",
    ]
    for t in tests:
        code = redirect_url(t)
        print(f"{t} -> {code}")