def render_response_from_env(env):
    template = env.get('template', '')
    name = env.get('request', {}).get('name', '')
    return template.replace('{name}', name)

def home(env):
    return render_response_from_env(env)

if __name__ == "__main__":
    env1 = {'template': 'Hello, {name}!', 'request': {'name': 'Alice'}}
    env2 = {'template': 'Welcome {name} to the system.', 'request': {'name': 'Bob'}}
    env3 = {'template': 'Goodbye, {name}.', 'request': {'name': 'Charlie'}}
    env4 = {'template': '{name}, your order is ready.', 'request': {'name': ''}}
    env5 = {'template': 'Hi {name}, hi again {name}!', 'request': {'name': 'Dana'}}

    print(home(env1))
    print(home(env2))
    print(home(env3))
    print(home(env4))
    print(home(env5))