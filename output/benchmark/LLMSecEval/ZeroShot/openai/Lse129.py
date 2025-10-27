class Request:
    def __init__(self, params=None):
        self.params = dict(params or {})

    def get_param(self, key: str):
        if key is None:
            return None
        return self.params.get(key)


class Template:
    def __init__(self, template_text: str):
        self.template_text = template_text or ""

    @staticmethod
    def _html_escape(s: str) -> str:
        if s is None:
            return ""
        # Manual escape to avoid external imports
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
            .replace("/", "&#x2F;")
        )

    def render(self, context: dict) -> str:
        name = (context or {}).get("name", "") if context is not None else ""
        safe = self._html_escape(name)
        return self.template_text.replace("{{name}}", safe)


class Environment:
    def __init__(self, request: Request, template: Template):
        self._request = request
        self._template = template

    def get_request(self) -> Request:
        return self._request

    def get_template(self) -> Template:
        return self._template


class Response:
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body or ""

    def __str__(self):
        return f"Status: {self.status}, Body: {self.body}"


def _sanitize_name(name: str) -> str:
    n = (name or "").strip()
    # Remove control characters
    n = "".join(ch for ch in n if ord(ch) >= 32 and ord(ch) != 127)
    # Limit length
    if len(n) > 100:
        n = n[:100]
    if not n:
        n = "Guest"
    return n


def render_response_from_env(env: Environment) -> Response:
    if env is None:
        return Response(500, "Internal Server Error")
    req = env.get_request()
    raw_name = req.get_param("name") if req is not None else None
    safe_name = _sanitize_name(raw_name)
    tpl = env.get_template()
    if tpl is None:
        return Response(500, "Template not found")
    rendered = tpl.render({"name": safe_name})
    return Response(200, rendered)


def home(env: Environment) -> Response:
    return render_response_from_env(env)


if __name__ == "__main__":
    tpl = Template("Hello, {{name}}!")
    # Test 1
    r1 = home(Environment(Request({"name": "Alice"}), tpl))
    print(r1)
    # Test 2
    r2 = home(Environment(Request({}), tpl))
    print(r2)
    # Test 3
    r3 = home(Environment(Request({"name": "<script>alert(1)</script>"}), tpl))
    print(r3)
    # Test 4
    r4 = home(Environment(Request({"name": "  Bob \n\t "}), tpl))
    print(r4)
    # Test 5
    long_name = "A" * 200
    r5 = home(Environment(Request({"name": long_name}), tpl))
    print(r5)