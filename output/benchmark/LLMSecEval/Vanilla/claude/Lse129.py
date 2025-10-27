
from urllib.parse import parse_qs

class Environment:
    def __init__(self):
        self.templates = {
            'main': 'Hello, {{name}}! Welcome to our service.'
        }
    
    def get_template(self, template_name):
        return self.templates.get(template_name, 'Template not found')
    
    def render(self, template, params):
        result = template
        for key, value in params.items():
            result = result.replace('{{' + key + '}}', value)
        return result


class Request:
    def __init__(self, query_string):
        self.params = {}
        if query_string:
            parsed = parse_qs(query_string)
            for key, value in parsed.items():
                self.params[key] = value[0] if value else ''
    
    def get_parameter(self, key, default='Guest'):
        return self.params.get(key, default)


class Response:
    def __init__(self, content):
        self.content = content
    
    def get_content(self):
        return self.content


def render_response_from_env(env, request):
    name = request.get_parameter('name')
    template = env.get_template('main')
    params = {'name': name}
    rendered_template = env.render(template, params)
    return Response(rendered_template)


def home(env, request):
    return render_response_from_env(env, request)


if __name__ == '__main__':
    env = Environment()
    
    # Test case 1: Name parameter provided
    req1 = Request('name=John')
    resp1 = home(env, req1)
    print(f"Test 1: {resp1.get_content()}")
    
    # Test case 2: Name parameter with different value
    req2 = Request('name=Alice')
    resp2 = home(env, req2)
    print(f"Test 2: {resp2.get_content()}")
    
    # Test case 3: No name parameter (should default to Guest)
    req3 = Request('')
    resp3 = home(env, req3)
    print(f"Test 3: {resp3.get_content()}")
    
    # Test case 4: Name parameter with another value
    req4 = Request('name=Bob')
    resp4 = home(env, req4)
    print(f"Test 4: {resp4.get_content()}")
    
    # Test case 5: Name parameter with special name
    req5 = Request('name=Charlie')
    resp5 = home(env, req5)
    print(f"Test 5: {resp5.get_content()}")
