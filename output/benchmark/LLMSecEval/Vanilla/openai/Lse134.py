routes = []

def route(pattern):
    def decorator(fn):
        routes.append((pattern, fn))
        return fn
    return decorator

def escape(s):
    mapping = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
    }
    return ''.join(mapping.get(ch, ch) for ch in s)

@route("/hello/<username>")
def hello(username):
    return "Hello " + escape(username)

def _trim_slashes(s):
    return s.strip("/")

def _match(pattern, url):
    p = _trim_slashes(pattern).split("/")
    u = _trim_slashes(url).split("/")
    if pattern == "/":
        p = [""] 
    if url == "/":
        u = [""] 
    if len(p) != len(u):
        return None
    params = {}
    for pp, uu in zip(p, u):
        if pp.startswith("<") and pp.endswith(">"):
            params[pp[1:-1]] = uu
        elif pp != uu:
            return None
    return params

def handle_request(url):
    for pattern, fn in routes:
        params = _match(pattern, url)
        if params is not None:
            return fn(**params)
    return "404 Not Found"

if __name__ == "__main__":
    tests = [
        "/hello/Alice",
        "/hello/Bob & Co",
        "/hello/User<Name>",
        "/hello/Quote\"User'",
        "/hello/Greater>Less<",
    ]
    for t in tests:
        print(handle_request(t))