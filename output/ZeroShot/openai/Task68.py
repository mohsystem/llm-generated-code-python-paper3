import sys
import json

def _escape_ldap_filter(value: str) -> str:
    if value is None:
        return ""
    out = []
    for ch in value:
        code = ord(ch)
        if ch == '\\':
            out.append("\\5c")
        elif ch == '*':
            out.append("\\2a")
        elif ch == '(':
            out.append("\\28")
        elif ch == ')':
            out.append("\\29")
        elif code == 0:
            out.append("\\00")
        elif code < 0x20 or code == 0x7F:
            out.append("\\%02x" % code)
        else:
            out.append(ch)
    return "".join(out)

def _escape_dn_value(value: str) -> str:
    if value is None:
        return ""
    res = []
    for i, ch in enumerate(value):
        must_escape = False
        if i == 0 and (ch == ' ' or ch == '#'):
            must_escape = True
        if i == len(value) - 1 and ch == ' ':
            must_escape = True
        if ch in {',', '+', '"', '\\', '<', '>', ';', '='}:
            must_escape = True
        if must_escape:
            res.append('\\' + ch)
        else:
            res.append(ch)
    return "".join(res)

def _plausible_domain(domain: str) -> bool:
    if not isinstance(domain, str) or not domain or len(domain) > 253 or '..' in domain:
        return False
    labels = domain.split('.')
    if not labels:
        return False
    for label in labels:
        if not (1 <= len(label) <= 63):
            return False
        if label[0] == '-' or label[-1] == '-':
            return False
        for ch in label:
            if not (ch.isalnum() or ch == '-'):
                return False
    return True

def _plausible_username(username: str) -> bool:
    if not isinstance(username, str) or not (1 <= len(username) <= 128):
        return False
    for ch in username:
        if not (ch.isalnum() or ch in '._-'):
            return False
    return True

def _base_dn_from_domain(domain: str) -> str:
    return ",".join("dc=" + _escape_dn_value(part) for part in domain.split('.'))

def find_user(domain: str, username: str) -> str:
    if not _plausible_domain(domain):
        return json.dumps({"error": "invalid_domain"})
    if not _plausible_username(username):
        return json.dumps({"error": "invalid_username"})

    base_dn = _base_dn_from_domain(domain)
    filt = f"(uid={_escape_ldap_filter(username)})"

    try:
        from ldap3 import Server, Connection, SUBTREE
    except Exception:
        return json.dumps({"error": "ldap3_not_installed"})

    try:
        server = Server('127.0.0.1', port=389, use_ssl=False, get_info=None)
        conn = Connection(server, user=None, password=None, auto_bind=True, receive_timeout=5)
        ok = conn.search(search_base=base_dn, search_filter=filt, search_scope=SUBTREE, attributes=['cn','uid','mail'], size_limit=1)
        if not ok or len(conn.response) == 0:
            try:
                conn.unbind()
            except Exception:
                pass
            return json.dumps({"result": None})
        entry = conn.response[0]
        dn = entry.get('dn', '')
        attrs = entry.get('attributes', {}) or {}
        result = {
            "dn": dn,
            "cn": (attrs.get('cn') if isinstance(attrs.get('cn'), str) else (attrs.get('cn')[0] if attrs.get('cn') else "")) or "",
            "uid": (attrs.get('uid') if isinstance(attrs.get('uid'), str) else (attrs.get('uid')[0] if attrs.get('uid') else "")) or "",
            "mail": (attrs.get('mail') if isinstance(attrs.get('mail'), str) else (attrs.get('mail')[0] if attrs.get('mail') else "")) or "",
        }
        try:
            conn.unbind()
        except Exception:
            pass
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": type(e).__name__})

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        print(find_user(sys.argv[1], sys.argv[2]))
    else:
        print(find_user("example.com", "jdoe"))
        print(find_user("example.com", "alice"))
        print(find_user("sub.example.com", "bob_smith"))
        print(find_user("invalid_domain!", "user"))
        print(find_user("example.com", "bad*user"))