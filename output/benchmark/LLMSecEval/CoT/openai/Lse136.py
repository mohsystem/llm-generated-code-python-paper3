def _hex_val(c: str) -> int:
    if '0' <= c <= '9':
        return ord(c) - ord('0')
    if 'a' <= c <= 'f':
        return ord(c) - ord('a') + 10
    if 'A' <= c <= 'F':
        return ord(c) - ord('A') + 10
    return -1

def _url_decode(s: str) -> str:
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == '+':
            out.append(' ')
        elif c == '%' and i + 2 < n:
            hi = _hex_val(s[i+1])
            lo = _hex_val(s[i+2])
            if hi >= 0 and lo >= 0:
                out.append(chr((hi << 4) + lo))
                i += 2
            else:
                out.append('%')
        else:
            out.append(c)
        i += 1
    return ''.join(out)

def _split_path_query(url: str):
    qmark = url.find('?')
    query = url[qmark+1:] if qmark != -1 else ''
    scheme_idx = url.find('://')
    if scheme_idx != -1:
        slash = url.find('/', scheme_idx + 3)
        if slash != -1:
            path = url[slash:qmark if qmark != -1 else len(url)]
        else:
            path = '/'
    else:
        path = url[:qmark] if qmark != -1 else url
    return path, query

def check_mod(url: str) -> str:
    CORRECT_USER = "admin"
    CORRECT_PASS = "secret"
    path, query = _split_path_query(url)
    if path != "/check_mod":
        return "false"
    params = {}
    if query:
        for pair in query.split('&'):
            if not pair:
                continue
            if '=' in pair:
                k, v = pair.split('=', 1)
            else:
                k, v = pair, ''
            params[_url_decode(k)] = _url_decode(v)
    if params.get("username") == CORRECT_USER and params.get("password") == CORRECT_PASS:
        return "true"
    return "false"

if __name__ == "__main__":
    tests = [
        "/check_mod?username=admin&password=secret",
        "/check_mod?username=admin&password=wrong",
        "/other?username=admin&password=secret",
        "http://example.com/check_mod?username=admin&password=sec%72et",
        "/check_mod?password=secret&username=admin",
    ]
    for t in tests:
        print(check_mod(t))