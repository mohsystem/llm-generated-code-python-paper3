import sys

def dc_to_base_dn(dc: str) -> str:
    if dc is None:
        return ""
    t = dc.strip()
    if "dc=" in t.lower():
        return t
    parts = [p.strip() for p in t.replace('.', ',').split(',') if p.strip()]
    return ",".join(f"dc={p}" for p in parts)

def ldap_escape(s: str) -> str:
    if s is None:
        return ""
    out = []
    for ch in s:
        if ch == '\\':
            out.append("\\5c")
        elif ch == '*':
            out.append("\\2a")
        elif ch == '(':
            out.append("\\28")
        elif ch == ')':
            out.append("\\29")
        elif ch == '\x00':
            out.append("\\00")
        else:
            out.append(ch)
    return ''.join(out)

def query_ldap(dc: str, username: str) -> str:
    base_dn = dc_to_base_dn(dc)
    flt = f"(|(uid={ldap_escape(username)})(sAMAccountName={ldap_escape(username)})(cn={ldap_escape(username)}))"
    try:
        from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES
        server = Server('localhost', port=389)
        conn = Connection(server, auto_bind=True)
        ok = conn.search(search_base=base_dn, search_filter=flt, search_scope=SUBTREE, attributes=ALL_ATTRIBUTES)
        if ok and conn.entries:
            # entry_to_json returns a JSON string
            return conn.entries[0].entry_to_json()
        else:
            return "NOT_FOUND"
    except Exception as e:
        return f"ERROR: {e}"

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        print(query_ldap(sys.argv[1], sys.argv[2]))
    else:
        tests = [
            ("example.com", "alice"),
            ("example.com", "bob"),
            ("dc=example,dc=com", "carol"),
            ("example,org", "dave"),
            ("test.local", "eve"),
        ]
        for dc, user in tests:
            print(f"DC={dc} USER={user}")
            print(query_ldap(dc, user))