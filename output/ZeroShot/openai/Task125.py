import re
from typing import List, Dict, Set

SAFE = re.compile(r'^[a-z0-9_-]{1,32}$')

USER_ROLES: Dict[str, str] = {
    "alice": "admin",
    "bob": "editor",
    "carol": "viewer",
    "dave": "viewer",
    "eve": "editor",
}

ROLE_RESOURCES: Dict[str, Set[str]] = {
    "admin": {"config", "reports", "dashboard", "users", "logs"},
    "editor": {"reports", "dashboard"},
    "viewer": {"dashboard"},
}

def _canonicalize(s: str) -> str | None:
    if not isinstance(s, str):
        return None
    v = s.strip().lower()
    if SAFE.fullmatch(v) is None:
        return None
    return v

def get_accessible_resources(username: str) -> List[str]:
    u = _canonicalize(username)
    if u is None:
        return []
    role = USER_ROLES.get(u)
    if role is None:
        return []
    res = ROLE_RESOURCES.get(role, set())
    return sorted(list(res))

def can_access(username: str, resource: str) -> bool:
    u = _canonicalize(username)
    r = _canonicalize(resource)
    if u is None or r is None:
        return False
    role = USER_ROLES.get(u)
    if role is None:
        return False
    return r in ROLE_RESOURCES.get(role, set())

def request_access(username: str, resource: str) -> str:
    return f"GRANTED: {username} -> {resource}" if can_access(username, resource) else f"DENIED: {username} -> {resource}"

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ("alice", "logs"),
        ("bob", "config"),
        ("carol", "dashboard"),
        ("unknown", "reports"),
        ("eve", "reports"),
    ]
    for user, res in tests:
        print(request_access(user, res))

    for user in ["alice", "bob", "carol", "unknown", "eve"]:
        print(f"Resources for {user}: {get_accessible_resources(user)}")