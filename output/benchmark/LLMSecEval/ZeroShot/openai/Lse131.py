def escape_html(s: str) -> str:
    if s is None:
        return ""
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

def render_response_from_env(env: dict, request: dict) -> str:
    env = env or {}
    request = request or {}
    name = request.get("name", "")
    template = env.get("template")
    if template is None or len(template) > 10000:
        template = "Hello, {{name}}"
    escaped_name = escape_html(str(name))
    return template.replace("{{name}}", escaped_name)

def home(env: dict, request: dict) -> str:
    return render_response_from_env(env, request)

if __name__ == "__main__":
    env = {"template": "<h1>Welcome, {{name}}</h1>"}
    tests = [
        {"name": "Alice"},
        {"name": "<script>alert(1)</script>"},
        {},
        {"name": "O'Reilly & Co"},
        {"name": "A" * 50},
    ]
    for i, req in enumerate(tests, 1):
        print(f"Test {i}: {home(env, req)}")