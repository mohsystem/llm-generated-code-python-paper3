import re

SAFE_TARGET_PATTERN = re.compile(r'^[A-Za-z0-9-]+\.')
MAX_TARGET_LENGTH = 2048

def get_redirect_url(target_param: str) -> str:
    if target_param is None:
        return "/"
    target = target_param.strip()
    if not target or len(target) > MAX_TARGET_LENGTH:
        return "/"
    if any(c in target for c in ("\r", "\n")):
        return "/"
    if SAFE_TARGET_PATTERN.search(target):
        return target
    return "/"

if __name__ == "__main__":
    tests = [
        "example.com/home",
        "sub-domain.example",
        "/internal/path",
        "http://evil.com",
        "bad..com"
    ]
    for t in tests:
        print(f"Input: {t} => Redirect: {get_redirect_url(t)}")