import re

ALLOWED = re.compile(r'^https://(www\.)?example\.com(/[A-Za-z0-9._~\-/%?#&=]*)?$', re.ASCII)
MAX_LEN = 2048
SAFE_FALLBACK = "https://www.example.com/"

def _has_ctl(s: str) -> bool:
    return any((ord(ch) < 0x20 or ord(ch) == 0x7F) for ch in s)

def _sanitize_default(def_url: str | None) -> str:
    if not def_url:
        return SAFE_FALLBACK
    if len(def_url) > MAX_LEN:
        return SAFE_FALLBACK
    if _has_ctl(def_url):
        return SAFE_FALLBACK
    if not def_url.startswith("https://"):
        return SAFE_FALLBACK
    return def_url

def resolve_redirect(target_url: str | None, default_url: str | None) -> str:
    safe_default = _sanitize_default(default_url)
    if target_url is None:
        return safe_default
    if len(target_url) == 0 or len(target_url) > MAX_LEN:
        return safe_default
    if _has_ctl(target_url):
        return safe_default
    if ALLOWED.fullmatch(target_url):
        return target_url
    return safe_default

if __name__ == "__main__":
    default_url = "https://www.example.com/safe"
    tests = [
        "https://www.example.com/path?x=1",   # allowed
        "https://evil.com/",                  # wrong domain
        "http://www.example.com/",            # wrong scheme
        None,                                 # None
        "https://www.example.com/\r\nattack"  # CRLF injection attempt
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {resolve_redirect(t, default_url)}")