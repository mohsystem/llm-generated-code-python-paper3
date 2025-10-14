def escape_html(s: str) -> str:
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

def display_on_web(user_input: str) -> str:
    if user_input is None:
        user_input = ""
    escaped = escape_html(user_input)
    return f"<!doctype html><html><head><meta charset=\"utf-8\"><title>Echo</title></head><body><h1>Echo</h1><pre>{escaped}</pre></body></html>"

if __name__ == "__main__":
    tests = [
        "Hello, world!",
        "<script>alert('xss')</script>",
        "Tom & Jerry",
        "Quotes: \"double\" and 'single'",
        "Line1\nLine2\tTabbed"
    ]
    for t in tests:
        print(display_on_web(t))