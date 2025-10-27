import re
import urllib.parse

def get_redirect(query: str) -> str:
    target = _get_query_param(query, "target")
    if target is None:
        return "/"
    decoded = urllib.parse.unquote_plus(target)
    pattern = re.compile(r'^[A-Za-z0-9-]+\..*')
    return decoded if pattern.fullmatch(decoded) else "/"

def _get_query_param(query: str, key: str):
    if query is None:
        return None
    # Simple parser without importing urlparse to keep everything in one file context
    for part in query.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        if k == key:
            return v
    return None

if __name__ == "__main__":
    tests = [
        "target=sub.example.com",
        "target=http%3A%2F%2Fevil.com",
        "target=foo.bar/baz",
        "page=home",
        "target=foo."
    ]
    for q in tests:
        print(get_redirect(q))