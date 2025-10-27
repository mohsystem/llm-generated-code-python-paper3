import re

# 1) Problem understanding:
# - Compile regex once on module load.
# - Validate target URL against regex only to decide if it's allowed.
# - If allowed, return target; else return default.
# - Do not use regex to construct redirect URL.

# 2) Security requirements:
# - No user-controlled regex construction.
# - Cap input length (defensive).
# - Provide safe fallback default.

# 3) Secure coding generation:
_MAX_URL_LENGTH = 2048
_ALLOWED_URL_PATTERN = re.compile(
    r"^https://(www\.)?example\.com(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?(\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?(#[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?$",
    re.IGNORECASE
)

def determine_redirect(target_url: str, default_url: str) -> str:
    safe_default = default_url if default_url and default_url.strip() else "https://example.com/"
    if not target_url:
        return safe_default
    if len(target_url) > _MAX_URL_LENGTH:
        return safe_default
    if _ALLOWED_URL_PATTERN.fullmatch(target_url):
        return target_url
    return safe_default

# 4) Code review and 5) Secure code output: tests
if __name__ == "__main__":
    default_url = "https://safe.example.org/home"
    tests = [
        "https://example.com/welcome",
        "https://www.example.com/path?item=42#section",
        "https://evil.com/phish",
        "http://example.com/insecure",
        ""
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {determine_redirect(t, default_url)}")