import re
from urllib.parse import parse_qsl, unquote_plus

SAFE_PREFIX = re.compile(r'^[A-Za-z0-9-]+\..*')
MAX_QUERY_LEN = 4096
MAX_VALUE_LEN = 2048

def determine_redirect(query_string: str) -> str:
    if query_string is None:
        return "/"
    if len(query_string) > MAX_QUERY_LEN:
        return "/"
    target = None
    # parse_qsl preserves order; we take the first 'target'
    try:
        for k, v in parse_qsl(query_string, keep_blank_values=True, max_num_fields=200):
            if k == "target":
                target = unquote_plus(v)
                break
    except Exception:
        return "/"
    if target is None or len(target) == 0 or len(target) > MAX_VALUE_LEN:
        return "/"
    # ASCII printable only, no control characters
    if any((ord(c) < 0x20 or ord(c) == 0x7F or ord(c) > 0x7E) for c in target):
        return "/"
    if SAFE_PREFIX.match(target):
        return target
    return "/"

if __name__ == "__main__":
    tests = [
        "target=abc.example.com",         # valid
        "target=abc-",                    # invalid
        "other=1&target=-sub.example.org",# valid
        "x=1&target=foo.&y=2",            # valid
        "target=%0d%0ahttps://evil.com",  # invalid due to control chars
    ]
    for q in tests:
        print(f"Query: {q} -> Redirect: {determine_redirect(q)}")