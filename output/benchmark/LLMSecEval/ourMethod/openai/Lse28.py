import re
from typing import Optional

# Compiled once at module import
_ALLOW_RE = re.compile(r"^https://([A-Za-z0-9-]+\.)*example\.com(:[0-9]{1,5})?(/.*)?$", re.IGNORECASE)

_MAX_URL_LEN = 2048
_SAFE_DEFAULT = "https://www.example.com/"

def _is_allowed(url: Optional[str]) -> bool:
    if not isinstance(url, str):
        return False
    if len(url) == 0 or len(url) > _MAX_URL_LEN:
        return False
    if '\r' in url or '\n' in url:
        return False
    return _ALLOW_RE.fullmatch(url) is not None

def resolve_redirect(target_url: Optional[str], default_url: Optional[str]) -> str:
    """Return target_url if allowed by regex; otherwise a safe default.
    The regex is not used to construct the redirect URL."""
    safe_fallback = default_url if _is_allowed(default_url) else _SAFE_DEFAULT
    if _is_allowed(target_url):
        return str(target_url)
    return safe_fallback

if __name__ == "__main__":
    tests = [
        ("https://example.com/path", "https://www.example.com/home"),
        ("https://sub.example.com/", "https://www.example.com/fallback"),
        ("https://evil.com/", "https://www.example.com/fallback"),
        ("http://example.com/", "https://www.example.com/fallback"),
        ("https://example.com/" + ("a" * 2100), "http://insecure.example.com/"),
    ]
    for i, (t, d) in enumerate(tests, 1):
        res = resolve_redirect(t, d)
        shown_t = t if len(t) <= 80 else (t[:80] + "...")
        print(f"Test {i}:")
        print(f"  target = {shown_t}")
        print(f"  default= {d}")
        print(f"  result = {res}")