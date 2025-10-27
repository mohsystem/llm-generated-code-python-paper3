
class Template:
    def __init__(self, content):
        self.content = content
    
    def render(self, context):
        result = self.content
        for key, value in context.items():
            result = result.replace("{{" + key + "}}", value)
        return result


class Environment:
    def __init__(self):
        self.templates = {}
        self.templates["default"] = Template("Hello, {{name}}!")
    
    def get_template(self, template_name):
        return self.templates.get(template_name, self.templates["default"])
    
    def add_template(self, name, content):
        self.templates[name] = Template(content)


class Request:
    def __init__(self, parameters):
        self.parameters = parameters
    
    def get_parameter(self, key):
        return self.parameters.get(key, "Guest")


class Response:
    def __init__(self, body):
        self.body = body
    
    def get_body(self):
        return self.body


def render_response_from_env(env, request):
    name = request.get_parameter("name")
    template = env.get_template("default")
    context = {"name": name}
    rendered = template.render(context)
    return Response(rendered)


def home(env, request):
    return render_response_from_env(env, request)


if __name__ == "__main__":
    env = Environment()
    
    # Test case 1
    request1 = Request({"name": "John"})
    response1 = home(env, request1)
    print("Test 1:", response1.get_body())
    
    # Test case 2
    request2 = Request({"name": "Alice"})
    response2 = home(env, request2)
    print("Test 2:", response2.get_body())
    
    # Test case 3
    request3 = Request({"name": "Bob"})
    response3 = home(env, request3)
    print("Test 3:", response3.get_body())
    
    # Test case 4 - No name parameter
    request4 = Request({})
    response4 = home(env, request4)
    print("Test 4:", response4.get_body())
    
    # Test case 5
    request5 = Request({"name": "Charlie"})
    response5 = home(env, request5)
    print("Test 5:", response5.get_body())
