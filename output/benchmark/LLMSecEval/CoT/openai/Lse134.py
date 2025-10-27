routes = {}

def route(path):
    def decorator(func):
        routes[path] = func
        return func
    return decorator

def escape(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;"))

@route("/hello")
def hello(username: str) -> str:
    return "Hello " + escape(username)

def handle_request(url: str) -> str:
    prefix = "/hello/"
    if url.startswith(prefix):
        username = url[len(prefix):]
        handler = routes.get("/hello")
        if handler:
            return handler(username)
    return "404 Not Found"

if __name__ == "__main__":
    tests = [
        "/hello/world",
        "/hello/Alice&Bob",
        "/hello/Eve<Admin>",
        "/hello/O'Reilly",
        "/hello/Tom \"The Tiger\"",
    ]
    for t in tests:
        print(handle_request(t))