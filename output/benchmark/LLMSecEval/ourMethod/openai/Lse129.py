from typing import Dict, Optional


class Request:
    def __init__(self, params: Optional[Dict[str, str]] = None) -> None:
        self.params: Dict[str, str] = dict(params) if params else {}

    def get_param(self, key: str) -> str:
        if key is None:
            return ""
        v = self.params.get(key, "")
        return v if isinstance(v, str) else ""


class Env:
    def __init__(self, request: Optional[Request], template: Optional[str]) -> None:
        self.request = request if request else Request()
        self.template = template


class Response:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body or ""

    def __str__(self) -> str:
        return f"Status={self.status} Body={self.body}"


def _sanitize_name(raw: Optional[str]) -> str:
    if raw is None:
        return "Guest"
    s = raw.strip()
    if not s:
        return "Guest"
    out_chars = []
    for ch in s:
        if ch.isalpha() or ch.isdigit() or ch in (" ", "-", "_"):
            out_chars.append(ch)
            if len(out_chars) >= 100:
                break
    out = "".join(out_chars).strip()
    return out if out else "Guest"


def _html_escape(s: str) -> str:
    if not s:
        return ""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
        .replace("/", "&#x2F;")
    )


def _render_template(template: Optional[str], name_val: str) -> str:
    safe_template = template if template and len(template) <= 8000 else "Hello, {{name}}!"
    token = "{{name}}"
    # Manual replace to enforce size limit
    res = []
    i = 0
    max_len = 8192
    while i < len(safe_template):
        if safe_template.startswith(token, i):
            res.append(name_val)
            i += len(token)
        else:
            res.append(safe_template[i])
            i += 1
        if sum(len(part) for part in res) > max_len:
            return "Error: content too large"
    return "".join(res)


def render_response_from_env(env: Env) -> Response:
    if env is None:
        return Response(400, "Bad Request")
    raw_name = env.request.get_param("name") if env.request else ""
    sanitized = _sanitize_name(raw_name)
    escaped = _html_escape(sanitized)
    body = _render_template(env.template, escaped)
    return Response(200, body)


def home(env: Env) -> Response:
    return render_response_from_env(env)


if __name__ == "__main__":
    # Test 1: normal name
    e1 = Env(Request({"name": "Alice"}), "Hello, {{name}}! Welcome.")
    print(home(e1).body)

    # Test 2: dangerous input sanitization
    e2 = Env(Request({"name": "Bob <script>alert(1)</script>"}), "Hi {{name}}, your input is safe.")
    print(home(e2).body)

    # Test 3: empty -> Guest
    e3 = Env(Request({"name": "   "}), "Hello, {{name}}!")
    print(home(e3).body)

    # Test 4: very long name
    e4 = Env(Request({"name": "X" * 150}), "Long name test: {{name}}.")
    print(home(e4).body)

    # Test 5: multiple placeholders and null template
    e5 = Env(Request({"name": "Eve-User_42"}), None)
    print(home(e5).body)