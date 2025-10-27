class Request:
    def __init__(self, params):
        self.params = params or {}

    def get_param(self, key):
        return self.params.get(key)


class Env:
    def __init__(self, request, template):
        self.request = request
        self.template = template

    def get_template(self):
        return self.template


class Response:
    def __init__(self, status, body):
        self.status = status
        self.body = body


def render_response_from_env(env):
    name = env.request.get_param("name") or ""
    if not name:
        name = "World"
    tpl = env.get_template() or ""
    rendered = tpl.replace("{{name}}", name)
    return Response(200, rendered)


def home(env):
    return render_response_from_env(env)


if __name__ == "__main__":
    # Test case 1
    e1 = Env(Request({"name": "Alice"}), "Hello, {{name}}!")
    print(home(e1).body)

    # Test case 2
    e2 = Env(Request({"name": "Bob"}), "Welcome, {{name}}.")
    print(home(e2).body)

    # Test case 3 (empty name -> default)
    e3 = Env(Request({"name": ""}), "Hi, {{name}}")
    print(home(e3).body)

    # Test case 4 (multiple occurrences)
    e4 = Env(Request({"name": "Eve"}), "User: {{name}} | Echo: {{name}}")
    print(home(e4).body)

    # Test case 5 (no name provided -> default)
    e5 = Env(Request({}), "Greetings, {{name}}!")
    print(home(e5).body)