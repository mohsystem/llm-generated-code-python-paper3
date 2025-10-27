from typing import Optional, Dict

MAX_NAME_LEN = 100
MAX_TEMPLATE_LEN = 4096

class Env:
    def __init__(self, template: Optional[str], request_name: Optional[str]):
        self.template = template or ""
        self.request_name = request_name

class Response:
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body or ""

    def __repr__(self) -> str:
        return f"Status: {self.status}, Body: {self.body}"

def _sanitize_name(name: Optional[str]) -> str:
    if not name:
        return "Guest"
    out_chars = []
    for ch in name[:MAX_NAME_LEN]:
        if ch.isalnum() or ch in " -_.,":
            out_chars.append(ch)
        # drop anything else
    result = "".join(out_chars).strip()
    return result if result else "Guest"

def _escape_html(s: str) -> str:
    # escape in safe order
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    s = s.replace("'", "&#39;")
    return s

def _render_template(template: str, escaped_name: str) -> str:
    if len(template) > MAX_TEMPLATE_LEN:
        return "Invalid template"
    return template.replace("{name}", escaped_name)

def render_response_from_env(env: Env) -> Response:
    if env is None:
        return Response(400, "Invalid environment")
    sanitized = _sanitize_name(env.request_name)
    escaped = _escape_html(sanitized)
    rendered = _render_template(env.template, escaped)
    return Response(200, rendered)

def home(env: Env) -> Response:
    return render_response_from_env(env)

if __name__ == "__main__":
    tests = [
        Env("Hello, {name}!", "Alice"),
        Env("<div>User: {name}</div>", "Bob <script>alert(1)</script>"),
        Env("Len test: {name}", "a" * 500),
        Env("Safe SQL-ish: {name}", "Eve; DROP TABLE users;--"),
        Env("Welcome!", None),
    ]
    for idx, t in enumerate(tests, 1):
        resp = home(t)
        print(f"Test {idx} -> {resp}")