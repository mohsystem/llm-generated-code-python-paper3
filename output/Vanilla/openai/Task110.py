import re

def validate_url(url: str) -> bool:
    if not url or any(ch.isspace() for ch in url):
        return False

    lower = url.lower()
    i = lower.find("://")
    if i <= 0:
        return False
    scheme = lower[:i]
    if scheme not in ("http", "https", "ftp"):
        return False

    pos = i + 3
    n = len(url)
    if pos >= n:
        return False

    def is_valid_port(s: str) -> bool:
        if not s.isdigit():
            return False
        try:
            p = int(s)
            return 1 <= p <= 65535
        except:
            return False

    def is_valid_ipv4(s: str) -> bool:
        parts = s.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            if len(p) == 0 or len(p) > 3 or not p.isdigit():
                return False
            if len(p) > 1 and p[0] == '0':
                return False
            v = int(p)
            if v < 0 or v > 255:
                return False
        return True

    def is_alnum(c: str) -> bool:
        return c.isdigit() or ('a' <= c.lower() <= 'z')

    def is_valid_domain(host: str) -> bool:
        if len(host) == 0 or len(host) > 253:
            return False
        if host.startswith(".") or host.endswith("."):
            return False
        labels = host.split(".")
        for label in labels:
            if len(label) < 1 or len(label) > 63:
                return False
            if not is_alnum(label[0]) or not is_alnum(label[-1]):
                return False
            for ch in label:
                if not (is_alnum(ch) or ch == '-'):
                    return False
        return True

    def is_hex(c: str) -> bool:
        return c.isdigit() or ('a' <= c.lower() <= 'f')

    def is_valid_ipv6(s: str) -> bool:
        if not s:
            return False
        t = s
        max_hextets = 8
        if '.' in t:
            last_colon = t.rfind(':')
            if last_colon < 0:
                return False
            ipv4 = t[last_colon+1:]
            if not is_valid_ipv4(ipv4):
                return False
            t = t[:last_colon]
            max_hextets = 6
        parts_dc = t.split("::")
        if len(parts_dc) > 2:
            return False
        hextet_count = 0
        for side in parts_dc:
            if not side:
                continue
            hs = side.split(":")
            for h in hs:
                if not (1 <= len(h) <= 4):
                    return False
                if not all(is_hex(ch) for ch in h):
                    return False
                hextet_count += 1
        if len(parts_dc) == 2:
            return hextet_count < max_hextets
        else:
            return hextet_count == max_hextets

    # Parse authority (host and optional port)
    if url[pos] == '[':
        close = url.find(']', pos + 1)
        if close < 0:
            return False
        host = url[pos + 1:close]
        if not is_valid_ipv6(host):
            return False
        pos = close + 1
        if pos < n and url[pos] == ':':
            pos += 1
            start = pos
            while pos < n and url[pos].isdigit():
                pos += 1
            if start == pos:
                return False
            if not is_valid_port(url[start:pos]):
                return False
    else:
        start = pos
        while pos < n and url[pos] not in (':', '/', '?', '#'):
            pos += 1
        if pos == start:
            return False
        host = url[start:pos]
        if ':' in host:
            return False
        if not (is_valid_ipv4(host) or is_valid_domain(host) or host.lower() == "localhost"):
            return False
        if pos < n and url[pos] == ':':
            pos += 1
            start = pos
            while pos < n and url[pos].isdigit():
                pos += 1
            if start == pos:
                return False
            if not is_valid_port(url[start:pos]):
                return False

    # Rest: path/query/fragment - ensure no whitespace (already ensured)
    return True


if __name__ == "__main__":
    tests = [
        "https://example.com",
        "http://sub.domain.co.uk:8080/path?query=1#frag",
        "ftp://192.168.1.1/resource",
        "https://[2001:db8::1]/index.html",
        "http://-invalid-.com"
    ]
    for t in tests:
        print(f"{t} -> {validate_url(t)}")