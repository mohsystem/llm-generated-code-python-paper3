class Request:
    def __init__(self, name: str):
        self.name = name

class Environment:
    def __init__(self, request: 'Request', template: str):
        self.request = request
        self.template = template

class Response:
    def __init__(self, body: str):
        self.body = body

def render_response_from_env(env: Environment) -> Response:
    tmpl = env.template if env and env.template is not None else ""
    name = env.request.name if env and env.request else None
    if not name:
        name = "World"
    rendered = tmpl.replace("{name}", name)
    return Response(rendered)

def home(env: Environment) -> Response:
    return render_response_from_env(env)

if __name__ == "__main__":
    tests = [
        Environment(Request("Alice"), "Hello, {name}!"),
        Environment(Request("Bob"), "Welcome, {name}."),
        Environment(Request(""), "Hi {name}"),
        Environment(Request("Charlie"), "{name} logged in"),
        Environment(Request("Dana"), "Bye, {name}! See you.")
    ]
    for t in tests:
        print(home(t).body)