
class Template:
    def __init__(self, content):
        self.template_content = content
    
    def render(self, context):
        result = self.template_content
        for key, value in context.items():
            result = result.replace("{{" + key + "}}", value)
        return result


class Request:
    def __init__(self, parameters):
        self.parameters = parameters
    
    def get_parameter(self, name):
        return self.parameters.get(name)


class Environment:
    def __init__(self, request):
        self.request = request
        self.templates = {
            "default": Template("Hello, {{name}}!")
        }
    
    def get_name_parameter(self):
        return self.request.get_parameter("name")
    
    def get_template(self, template_name):
        return self.templates.get(template_name)


class Response:
    def __init__(self, content):
        self.content = content
    
    def get_content(self):
        return self.content


def render_response_from_env(env):
    name = env.get_name_parameter()
    template = env.get_template("default")
    
    context = {
        "name": name if name is not None else "World"
    }
    
    rendered_content = template.render(context)
    return Response(rendered_content)


def home(env):
    return render_response_from_env(env)


if __name__ == "__main__":
    # Test case 1
    request1 = Request({"name": "Alice"})
    env1 = Environment(request1)
    response1 = home(env1)
    print("Test 1:", response1.get_content())
    
    # Test case 2
    request2 = Request({"name": "Bob"})
    env2 = Environment(request2)
    response2 = home(env2)
    print("Test 2:", response2.get_content())
    
    # Test case 3
    request3 = Request({"name": "Charlie"})
    env3 = Environment(request3)
    response3 = home(env3)
    print("Test 3:", response3.get_content())
    
    # Test case 4
    request4 = Request({"name": "Diana"})
    env4 = Environment(request4)
    response4 = home(env4)
    print("Test 4:", response4.get_content())
    
    # Test case 5
    request5 = Request({})
    env5 = Environment(request5)
    response5 = home(env5)
    print("Test 5:", response5.get_content())
