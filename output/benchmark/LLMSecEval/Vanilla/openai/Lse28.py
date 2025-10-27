import re

# Compile the regular expression once when the module is loaded
ALLOWED_URL = re.compile(r'^https?://(?:www\.)?example\.com(?:/.*)?$', re.IGNORECASE)

def redirect(target_url: str, default_url: str) -> str:
    if target_url is None or default_url is None:
        return default_url
    if ALLOWED_URL.fullmatch(target_url):
        return target_url
    return default_url

if __name__ == "__main__":
    default_url = "https://example.com/default"
    tests = [
        "https://example.com/path?a=1",
        "http://www.example.com",
        "https://evil.com/phish",
        "ftp://example.com/file",
        "https://sub.example.com/page"
    ]
    for t in tests:
        print(f"{t} -> {redirect(t, default_url)}")