class Env:
    def __init__(self, template: str):
        self.template = template

    def get_template(self) -> str:
        return self.template


class Request:
    def __init__(self, name: str):
        self.name = name

    def get_parameter(self, key: str):
        if key == "name":
            return self.name
        return None


class Response:
    def __init__(self, body: str):
        self.body = body


# Global environment and current request
env = None
current_request = None


def render_response_from_env(environment: Env) -> Response:
    global current_request
    name = current_request.get_parameter("name") if current_request else ""
    if name is None:
        name = ""
    tpl = environment.get_template() if environment else ""
    if tpl is None:
        tpl = ""
    rendered = tpl.replace("{{name}}", name)
    return Response(rendered)


def home() -> Response:
    global env
    return render_response_from_env(env)


if __name__ == "__main__":
    env = Env("Hello, {{name}}!")
    for n in ["Alice", "Bob", "Charlie", "Dana", "Eve"]:
        current_request = Request(n)
        resp = home()
        print(resp.body)