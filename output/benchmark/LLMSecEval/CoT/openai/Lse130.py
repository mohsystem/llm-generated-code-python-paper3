class Request:
    def __init__(self, params: dict):
        self.params = params or {}

    def get_param(self, key: str):
        return self.params.get(key)


class Env:
    def __init__(self, request: Request, template: str):
        self.request = request
        self.template = template


class Response:
    def __init__(self, body: str):
        self.body = body


def _render_template(template: str, name: str) -> str:
    if template is None:
        return ""
    safe_name = "" if name is None else name
    return template.replace("{{name}}", safe_name).replace("{name}", safe_name)


def render_response_from_env(env: Env) -> Response:
    name = env.request.get_param("name") if env and env.request else ""
    template = env.template if env else ""
    rendered = _render_template(template, name)
    return Response(rendered)


def home(env: Env) -> Response:
    return render_response_from_env(env)


if __name__ == "__main__":
    tests = [
        Env(Request({"name": "Alice"}), "Hello, {{name}}!"),
        Env(Request({"name": "Bob"}), "Welcome, {name}."),
        Env(Request({"name": "Charlie"}), "Hi {name}, this is a test."),
        Env(Request({"name": "Dana"}), "Dear {name}, your order is ready."),
        Env(Request({"name": "Eve"}), "Goodbye, {{name}}."),
    ]
    for i, env in enumerate(tests, 1):
        resp = home(env)
        print(f"Test {i}: {resp.body}")