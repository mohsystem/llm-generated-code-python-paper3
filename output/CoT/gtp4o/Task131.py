# Chain-of-Through process in code generation:
# 1) Understand: Safely deserialize a constrained custom format string to structured data.
# 2) Security: No unsafe eval/pickle, strict schema, size limits, allowlist for roles.
# 3) Implement: Defensive parsing and validation.
# 4) Review: Avoid regex DoS; simple scans; explicit limits.
# 5) Output: Canonical JSON or error string.

MAX_INPUT_LENGTH = 1024
ALLOWED_KEYS = {"name", "age", "email", "roles"}
ALLOWED_ROLES = {"user","admin","moderator","viewer","editor"}

def _is_valid_name(s: str) -> bool:
    if not (1 <= len(s) <= 50):
        return False
    for c in s:
        if not (c.isalpha() or c in " -'"):
            return False
    return True

def _parse_age(s: str):
    if not (1 <= len(s) <= 3) or not s.isdigit():
        return None
    val = int(s)
    if 0 <= val <= 120:
        return val
    return None

def _is_valid_email(s: str) -> bool:
    if not (6 <= len(s) <= 100):
        return False
    if s.count('@') != 1:
        return False
    local, domain = s.split('@', 1)
    if not local or not domain:
        return False
    # local
    for c in local:
        if not (c.isalnum() or c in "._%+-"):
            return False
    # domain
    if domain.startswith('.') or domain.endswith('.') or '..' in domain:
        return False
    for c in domain:
        if not (c.isalnum() or c in ".-"):
            return False
    if '.' not in domain:
        return False
    tld = domain.rsplit('.', 1)[-1]
    if not (2 <= len(tld) <= 10) or not tld.isalpha():
        return False
    return True

def _parse_roles(s: str):
    if not (1 <= len(s) <= 200):
        return None
    parts = [p.strip() for p in s.split(',')]
    if not parts or len(parts) > 5:
        return None
    out = []
    seen = set()
    for r in parts:
        if not r or r not in ALLOWED_ROLES:
            return None
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out

def _escape_json(s: str) -> str:
    sb = []
    for c in s:
        if c == '"':
            sb.append('\\"')
        elif c == '\\':
            sb.append('\\')
        elif c == '\b':
            sb.append('\\b')
        elif c == '\f':
            sb.append('\\f')
        elif c == '\n':
            sb.append('\\n')
        elif c == '\r':
            sb.append('\\r')
        elif c == '\t':
            sb.append('\\t')
        elif ord(c) < 0x20:
            sb.append('\\u%04x' % ord(c))
        else:
            sb.append(c)
    return ''.join(sb)

def deserialize_user_data(input_str: str) -> str:
    if input_str is None:
        return "ERROR: null input"
    if len(input_str) == 0:
        return "ERROR: empty input"
    if len(input_str) > MAX_INPUT_LENGTH:
        return "ERROR: input too long"
    if input_str.count(';') > 15:
        return "ERROR: too many fields"
    kv = {}
    for pair in filter(None, input_str.split(';')):
        if '=' not in pair:
            return "ERROR: invalid key=value pair"
        key, val = pair.split('=', 1)
        key = key.strip()
        val = val.strip()
        if key not in ALLOWED_KEYS:
            return "ERROR: unknown key: " + key
        if key in kv:
            return "ERROR: duplicate key: " + key
        if not val:
            return "ERROR: empty value for " + key
        kv[key] = val
    for req in ALLOWED_KEYS:
        if req not in kv:
            return "ERROR: missing required field: " + req
    name = kv["name"]
    age_str = kv["age"]
    email = kv["email"]
    roles_str = kv["roles"]

    if not _is_valid_name(name):
        return "ERROR: invalid name"
    age = _parse_age(age_str)
    if age is None:
        return "ERROR: invalid age"
    if not _is_valid_email(email):
        return "ERROR: invalid email"
    roles = _parse_roles(roles_str)
    if roles is None:
        return "ERROR: invalid roles"

    # JSON-like output
    roles_json = ",".join(f"\"{r}\"" for r in roles)
    return f"{{\"name\":\"{_escape_json(name)}\",\"age\":{age},\"email\":\"{_escape_json(email)}\",\"roles\":[{roles_json}]}}"

if __name__ == "__main__":
    tests = [
        "name=Alice Johnson;age=30;email=alice.j@example.com;roles=user,editor",
        "name=Bob;age=45;email=bob@example.org;roles=admin,moderator,viewer",
        "name=Carol;age=abc;email=carol@example.com;roles=user",
        "name=Dan;age=25;email=dan@bad_domain;roles=user",
        "name=Eve;age=29;email=eve@example.com;roles=user;token=xyz",
    ]
    for t in tests:
        print(deserialize_user_data(t))
    big = "a"*1100
    print(deserialize_user_data(f"name={big};age=20;email=aa@bb.cc;roles=user"))