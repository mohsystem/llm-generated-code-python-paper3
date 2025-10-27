import re
from urllib.parse import parse_qs

SAFE_PREFIX = re.compile(r'^[A-Za-z0-9-]+\.')
MAX_LEN = 2048

def decide_redirect_from_query(query: str) -> str:
    if query is None:
        return "/"
    q = query[1:] if query.startswith("?") else query
    try:
        params = parse_qs(q, strict_parsing=False, keep_blank_values=True)
    except Exception:
        return "/"
    target_vals = params.get("target")
    if not target_vals:
        return "/"
    target = target_vals[0].strip()
    if not target or len(target) > MAX_LEN or "\r" in target or "\n" in target:
        return "/"
    if SAFE_PREFIX.search(target):
        return target
    return "/"

if __name__ == "__main__":
    tests = [
        "target=abc.",
        "target=abc.def",
        "foo=1&target=-hyphen.",
        "target=..evil",
        "foo=bar"
    ]
    for t in tests:
        print(decide_redirect_from_query(t))