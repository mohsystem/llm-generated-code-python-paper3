from urllib.parse import urlparse

def redirect_url(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc
    if not netloc:
        # Handle URLs without scheme by reparsing
        parsed = urlparse("//" + url)
        netloc = parsed.netloc
    # Strip credentials and port from netloc to get domain
    host_part = netloc.split('@')[-1]
    domain = host_part.split(':')[0].lower()
    if domain == "example.com":
        return f"Redirecting to {url}"
    return "404 Not Found"

if __name__ == "__main__":
    tests = [
        "http://example.com",
        "https://example.com/path",
        "http://example.com:8080/abc",
        "https://sub.example.com/home",
        "https://notexample.com"
    ]
    for t in tests:
        print(redirect_url(t))