import re

# Chain-of-Through Step 1: Problem understanding
# Provide secure access to predefined resources based on (user_id, role, resource_id).

# Chain-of-Through Step 2: Security requirements
# - Validate tokens (length/charset).
# - Normalize role and enforce whitelist.
# - Use in-memory resources only.

_TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
_ROLES = {"ADMIN", "USER", "GUEST"}

_RESOURCES = {
    "doc_public": {"content": "Public Document", "roles": {"ADMIN", "USER", "GUEST"}},
    "doc_user":   {"content": "User Document",   "roles": {"ADMIN", "USER"}},
    "doc_admin":  {"content": "Admin Secrets",   "roles": {"ADMIN"}},
    "img_banner": {"content": "Image Banner",    "roles": {"ADMIN", "USER", "GUEST"}},
    "report_q3":  {"content": "Q3 Report",       "roles": {"ADMIN", "USER"}},
}

def _valid_token(s: str) -> bool:
    return isinstance(s, str) and bool(_TOKEN_RE.fullmatch(s))

# Chain-of-Through Step 3: Secure coding generation
def access_resource(user_id: str, role: str, resource_id: str) -> str:
    if any(v is None for v in (user_id, role, resource_id)):
        return "ERROR:INVALID_INPUT"
    if not _valid_token(user_id) or not _valid_token(resource_id):
        return "ERROR:INVALID_INPUT"
    norm_role = role.strip().upper()
    if norm_role not in _ROLES:
        return "ERROR:INVALID_INPUT"
    r = _RESOURCES.get(resource_id)
    if r is None:
        return "ERROR:NOT_FOUND"
    if norm_role not in r["roles"]:
        return "ERROR:ACCESS_DENIED"
    return f"OK:{resource_id}:{r['content']}"

# Chain-of-Through Step 4: Code review
# - Inputs are validated, roles/ids are constrained, outputs are simple and predictable.

# Chain-of-Through Step 5: Secure code output
if __name__ == "__main__":
    # 5 test cases
    tests = [
        ("alice", "user", "doc_user"),
        ("bob", "guest", "doc_admin"),
        ("carol", "ADMIN", "report_q3"),
        ("", "user", "doc_public"),
        ("dave", "user", "unknown"),
    ]
    for t in tests:
        print(access_resource(*t))