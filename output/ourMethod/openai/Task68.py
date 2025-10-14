import re
import sys
import json
from typing import List, Dict, Any

def _validate_domain(domain: str) -> str | None:
    if domain is None:
        return None
    d = domain.strip().lower()
    if len(d) < 3 or len(d) > 253:
        return None
    labels = d.split(".")
    if len(labels) < 1:
        return None
    pat = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    for label in labels:
        if not (1 <= len(label) <= 63):
            return None
        if not pat.fullmatch(label):
            return None
    return d

def _validate_username(username: str) -> str | None:
    if username is None:
        return None
    u = username.strip()
    if not (1 <= len(u) <= 64):
        return None
    if not re.fullmatch(r"[A-Za-z0-9._-]+", u):
        return None
    return u

def _escape_ldap_filter(value: str) -> str:
    out = []
    for ch in value:
        if ch == '\\':
            out.append(r"\5c")
        elif ch == '*':
            out.append(r"\2a")
        elif ch == '(':
            out.append(r"\28")
        elif ch == ')':
            out.append(r"\29")
        elif ch == '\x00':
            out.append(r"\00")
        else:
            out.append(ch)
    return "".join(out)

def _escape_ldap_dn_value(value: str) -> str:
    # minimal RFC 4514 escaping
    specials = {',', '+', '"', '\\', '<', '>', ';', '#', '='}
    out = []
    for ch in value:
        if ch in specials:
            out.append('\\' + ch)
        else:
            out.append(ch)
    s = "".join(out)
    if s.startswith(" "):
        s = "\\" + s
    if s.endswith(" "):
        s = s[:-1] + "\\ "
    return s

def _build_base_dn(domain: str) -> str:
    parts = domain.split(".")
    return ",".join(["dc=" + _escape_ldap_dn_value(p) for p in parts])

def search_user(domain: str, username: str) -> str:
    d = _validate_domain(domain)
    if d is None:
        return "ERROR: Invalid domain format."
    u = _validate_username(username)
    if u is None:
        return "ERROR: Invalid username format."
    base_dn = _build_base_dn(d)
    user_f = _escape_ldap_filter(u)
    filter_str = f"(&(objectClass=person)(|(uid={user_f})(sAMAccountName={user_f})(cn={user_f})))"

    try:
        import ldap3  # type: ignore
        server = ldap3.Server("localhost", port=389, use_ssl=False, get_info=None, connect_timeout=3)
        conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, receive_timeout=5, auto_bind=True)
        try:
            ok = conn.search(
                search_base=base_dn,
                search_filter=filter_str,
                search_scope=ldap3.SUBTREE,
                attributes=["cn", "uid", "sAMAccountName", "mail", "givenName", "sn"]
            )
            if not ok or len(conn.entries) == 0:
                return "NOT_FOUND"
            results: List[Dict[str, Any]] = []
            for e in conn.entries:
                dn = str(e.entry_dn)
                data = {
                    "dn": dn,
                    "cn": str(e.cn.value) if "cn" in e else "",
                    "uid": str(e.uid.value) if "uid" in e else "",
                    "sAMAccountName": str(e.sAMAccountName.value) if "sAMAccountName" in e else "",
                    "mail": str(e.mail.value) if "mail" in e else "",
                    "givenName": str(e.givenName.value) if "givenName" in e else "",
                    "sn": str(e.sn.value) if "sn" in e else "",
                }
                results.append(data)
            return json.dumps(results, ensure_ascii=False)
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
    except ImportError:
        return "ERROR: Python 'ldap3' library is not installed."
    except Exception as ex:
        msg = str(ex) if str(ex) else "LDAP operation failed."
        return f"ERROR: {msg}"

def _run_tests() -> None:
    tests = [
        ("example.com", "alice"),
        ("corp.local", "bob_smith"),
        ("test.org", "john.doe"),
        ("example.com", "invalid*user"),  # invalid
        ("bad_domain", "charlie"),        # invalid
    ]
    for dc, user in tests:
        print(f"Input: dc={dc} user={user}")
        print(search_user(dc, user))
        print("---")

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        print(search_user(sys.argv[1], sys.argv[2]))
    else:
        _run_tests()