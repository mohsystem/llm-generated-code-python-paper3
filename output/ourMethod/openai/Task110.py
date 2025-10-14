from typing import List

MAX_URL_LENGTH = 2048

def is_valid_url(s: str) -> bool:
    if s is None:
        return False
    if len(s) == 0 or len(s) > MAX_URL_LENGTH:
        return False
    # Disallow control/whitespace: only visible ASCII
    for ch in s:
        if ord(ch) < 0x21 or ord(ch) > 0x7E:
            return False

    scheme_sep = s.find("://")
    if scheme_sep <= 0:
        return False
    scheme = s[:scheme_sep].lower()
    if scheme not in ("http", "https", "ftp"):
        return False
    pos = scheme_sep + 3

    authority_end = _index_of_first(s, pos, ['/', '?', '#'])
    if authority_end == -1:
        authority_end = len(s)
    if authority_end <= pos:
        return False
    authority = s[pos:authority_end]
    if '@' in authority:
        return False

    port = -1
    host = ""

    if authority.startswith('['):
        close = authority.find(']')
        if close <= 1:
            return False
        host = authority[1:close]
        if not _is_valid_ipv6(host):
            return False
        rest = authority[close + 1:]
        if rest:
            if not rest.startswith(':'):
                return False
            port_str = rest[1:]
            if len(port_str) == 0 or len(port_str) > 5 or not port_str.isdigit():
                return False
            port = int(port_str)
            if port < 1 or port > 65535:
                return False
    else:
        colon = authority.rfind(':')
        if colon != -1:
            host = authority[:colon]
            port_str = authority[colon+1:]
            if len(port_str) == 0 or len(port_str) > 5 or not port_str.isdigit():
                return False
            port = int(port_str)
            if port < 1 or port > 65535:
                return False
        else:
            host = authority
        if not _is_valid_host(host):
            return False

    idx = authority_end
    # Path
    qpos = s.find('?', idx)
    fpos = s.find('#', idx)
    path_end = len(s)
    if qpos != -1:
        path_end = min(path_end, qpos)
    if fpos != -1:
        path_end = min(path_end, fpos)
    path = s[idx:path_end]
    if not _is_valid_path(path):
        return False

    # Query
    if qpos != -1:
        query_end = fpos if fpos != -1 else len(s)
        query = s[qpos+1:query_end]
        if not _is_valid_query_or_fragment(query):
            return False

    # Fragment
    if fpos != -1:
        frag = s[fpos+1:]
        if not _is_valid_query_or_fragment(frag):
            return False

    return True


def _index_of_first(s: str, start: int, chars: List[str]) -> int:
    idx = -1
    for ch in chars:
        i = s.find(ch, start)
        if i != -1:
            idx = i if idx == -1 else min(idx, i)
    return idx


def _is_valid_host(host: str) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    if _is_valid_ipv4(host):
        return True
    if len(host) > 253:
        return False
    labels = host.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not _is_valid_domain_label(label):
            return False
    tld = labels[-1]
    if len(tld) < 2:
        return False
    alpha_tld = all(('a' <= ch <= 'z') or ('A' <= ch <= 'Z') or ch == '-' for ch in tld)
    if not alpha_tld and not tld.lower().startswith('xn--'):
        return False
    return True


def _is_valid_domain_label(label: str) -> bool:
    if not label or len(label) > 63:
        return False
    if not _is_alnum(label[0]) or not _is_alnum(label[-1]):
        return False
    for ch in label:
        if not (_is_alnum(ch) or ch == '-'):
            return False
    return True


def _is_alnum(ch: str) -> bool:
    return ('A' <= ch <= 'Z') or ('a' <= ch <= 'z') or ('0' <= ch <= '9')


def _is_valid_ipv4(s: str) -> bool:
    parts = s.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if len(p) == 0 or len(p) > 3 or not p.isdigit():
            return False
        try:
            val = int(p)
        except ValueError:
            return False
        if val < 0 or val > 255:
            return False
    return True


def _is_valid_ipv6(s: str) -> bool:
    if not s:
        return False
    if s.count(':') < 2:
        return False
    ddc = s.find("::")
    has_dd = ddc != -1
    if has_dd and s.find("::", ddc + 2) != -1:
        return False

    left = s[:ddc] if has_dd else s
    right = s[ddc + 2:] if has_dd else ""

    left_parts = [] if left == "" else left.split(":")
    right_parts = [] if right == "" else right.split(":")

    if not _validate_ipv6_parts(left_parts):
        return False
    if not _validate_ipv6_parts(right_parts):
        return False

    parts_count = len(left_parts) + len(right_parts)
    if has_dd:
        return parts_count < 8
    else:
        return parts_count == 8


def _validate_ipv6_parts(parts: List[str]) -> bool:
    for part in parts:
        if part == "" or len(part) > 4:
            return False
        for ch in part:
            if not _is_hex(ch):
                return False
    return True


def _is_hex(ch: str) -> bool:
    return ('0' <= ch <= '9') or ('A' <= ch <= 'F') or ('a' <= ch <= 'f')


def _is_unreserved(ch: str) -> bool:
    return ('A' <= ch <= 'Z') or ('a' <= ch <= 'z') or ('0' <= ch <= '9') or ch in "-._~"


def _is_subdelim(ch: str) -> bool:
    return ch in "!$&'()*+,;="


def _is_pchar(ch: str) -> bool:
    return _is_unreserved(ch) or _is_subdelim(ch) or ch in (':', '@')


def _validate_percent(s: str, i: int) -> bool:
    if i + 2 >= len(s):
        return False
    return _is_hex(s[i+1]) and _is_hex(s[i+2])


def _is_valid_path(path: str) -> bool:
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == '%':
            if not _validate_percent(path, i):
                return False
            i += 3
            continue
        if ch == '/' or _is_pchar(ch):
            i += 1
            continue
        return False
    return True


def _is_valid_query_or_fragment(part: str) -> bool:
    i = 0
    while i < len(part):
        ch = part[i]
        if ch == '%':
            if not _validate_percent(part, i):
                return False
            i += 3
            continue
        if _is_pchar(ch) or ch in "/?":
            i += 1
            continue
        return False
    return True


if __name__ == "__main__":
    tests = [
        "https://example.com",
        "http://sub.example.co.uk:8080/path?query=ok#frag",
        "ftp://[2001:db8::1]/",
        "http://256.256.256.256",
        "https://example.com:70000",
    ]
    for t in tests:
        print(f"{t} -> {is_valid_url(t)}")