import io

def http_hello_page(username: str) -> str:
    u = "World" if (username is None or username == "") else username
    safe = _escape_html(u)
    body = f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>Hello</title></head><body><h1>Hello, {safe}!</h1></body></html>'
    response_stream = io.StringIO()
    response_stream.write(body)
    response_stream.close()
    # In a real server we'd flush/close the actual stream; here we return the body
    return body

def _escape_html(s: str) -> str:
    out = []
    for ch in s:
        if ch == '&':
            out.append("&amp;")
        elif ch == '<':
            out.append("&lt;")
        elif ch == '>':
            out.append("&gt;")
        elif ch == '"':
            out.append("&quot;")
        elif ch == "'":
            out.append("&#39;")
        else:
            out.append(ch)
    return "".join(out)

if __name__ == "__main__":
    tests = [
        "Alice",
        "",
        "Bob & Co",
        "<script>alert(1)</script>",
        "O'Neil"
    ]
    for t in tests:
        print(http_hello_page(t))