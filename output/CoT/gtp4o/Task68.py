import sys
import socket
from typing import List

def _escape_ldap_filter_value(value: str) -> str:
    if value is None:
        return ""
    out = []
    for ch in value:
        code = ord(ch)
        if ch == '*':
            out.append(r"\2a")
        elif ch == '(':
            out.append(r"\28")
        elif ch == ')':
            out.append(r"\29")
        elif ch == '\\':
            out.append(r"\5c")
        elif code == 0:
            out.append(r"\00")
        else:
            out.append(ch)
    return "".join(out)

def _is_valid_label(s: str) -> bool:
    if not s:
        return False
    if s[0] == '-' or s[-1] == '-':
        return False
    for ch in s:
        if not (ch.isalnum() or ch == '-'):
            return False
    return True

def _build_base_dn(dc_input: str) -> str:
    if dc_input is None:
        return "dc=localhost"
    s = dc_input.strip()
    if not s:
        return "dc=localhost"
    if '=' in s:
        parts = [p.strip() for p in s.split(',')]
        out: List[str] = []
        for p in parts:
            if '=' not in p:
                continue
            k, v = p.split('=', 1)
            if k.strip().lower() != 'dc':
                continue
            v2 = v.strip().lower()
            if _is_valid_label(v2):
                out.append(f"dc={v2}")
        return ",".join(out) if out else "dc=localhost"
    else:
        labels = [x.strip().lower() for x in s.split('.')]
        out = [f"dc={x}" for x in labels if _is_valid_label(x)]
        return ",".join(out) if out else "dc=localhost"

def search_user(dc_input: str, username: str) -> str:
    base_dn = _build_base_dn(dc_input)
    user_esc = _escape_ldap_filter_value((username or "").strip())
    filter_str = f"(|(uid={user_esc})(cn={user_esc})(sAMAccountName={user_esc})(userPrincipalName={user_esc}))"

    try:
        from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES, ALL
        server = Server('localhost', port=389, get_info=None)
        # Anonymous bind
        conn = Connection(server, auto_bind=True, receive_timeout=5)
        attrs = ["cn", "sn", "givenName", "uid", "mail", "sAMAccountName", "userPrincipalName"]
        ok = conn.search(search_base=base_dn, search_filter=filter_str, search_scope=SUBTREE, attributes=attrs, size_limit=1)
        if not ok or len(conn.entries) == 0:
            conn.unbind()
            return '{"error":"NOT_FOUND"}'
        entry = conn.entries[0]
        dn = entry.entry_dn
        # Build JSON-like string safely
        def esc(s: str) -> str:
            return s.replace('\\', '\\').replace('"', '\\"')
        buf = []
        buf.append('{"dn":"')
        buf.append(esc(dn))
        buf.append('","attributes":{')
        first = True
        for a in attrs:
            if a in entry:
                val = entry[a].value
                if not first:
                    buf.append(',')
                first = False
                buf.append(f'"{esc(a)}":')
                if isinstance(val, list):
                    buf.append('[')
                    for i, vv in enumerate(val):
                        if i > 0:
                            buf.append(',')
                        buf.append(f'"{esc(str(vv))}"')
                    buf.append(']')
                else:
                    buf.append(f'"{esc(str(val))}"')
        buf.append("}}")
        conn.unbind()
        return "".join(buf)
    except Exception as e:
        msg = f"{e.__class__.__name__}: {str(e) or ''}"
        msg = msg.replace('\\', '\\').replace('"', '\\"')
        return f'{{"error":"{msg}"}}'

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        print(search_user(sys.argv[1], sys.argv[2]))
    else:
        tests = [
            ("example.com", "alice"),
            ("dc=example,dc=com", "bob"),
            ("EXAMPLE.ORG", "charlie"),
            ("invalid$$domain", "dave"),
            ("dc=local,dc=domain", "eve"),
        ]
        for dc, user in tests:
            print(f"Input: dc={dc}, user={user}")
            print(search_user(dc, user))