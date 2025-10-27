class Request:
    def __init__(self, params):
        self.params = dict(params or {})

    def get_param(self, key, default=""):
        return self.params.get(key, default)


class Environment:
    def __init__(self, template, request):
        self.template = template
        self.request = request

    def get_template(self):
        return self.template


class Response:
    def __init__(self, content):
        self.content = content


def render_template(template, context):
    name = context.get("name", "")
    rendered = template.replace("{{ name }}", name)
    rendered = rendered.replace("{{name}}", name)
    return rendered


def render_response_from_env(env):
    name = env.request.get_param("name", "")
    template = env.get_template()
    rendered = render_template(template, {"name": name})
    return Response(rendered)


def home(env):
    return render_response_from_env(env)


if __name__ == "__main__":
    # Test case 1
    env1 = Environment("Hello, {{ name }}!", Request({"name": "Alice"}))
    print(home(env1).content)
    # Test case 2
    env2 = Environment("Welcome, {{name}}.", Request({"name": "Bob"}))
    print(home(env2).content)
    # Test case 3
    env3 = Environment("Hi {{ name }}, you're number {{ name }}", Request({"name": "Eve"}))
    print(home(env3).content)
    # Test case 4
    env4 = Environment("No placeholder here.", Request({"name": "Carol"}))
    print(home(env4).content)
    # Test case 5
    env5 = Environment("{{ name }} only", Request({}))  # missing name -> empty
    print(home(env5).content)