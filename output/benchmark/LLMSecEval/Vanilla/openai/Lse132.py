import re

# Simple template store
templates = {
    "hello.html": "Hello, {{ username }}!"
}

_routes = []

def _compile_pattern(pattern):
    names = []
    regex = '^'
    i = 0
    while i < len(pattern):
        if pattern[i] == '<':
            j = pattern.find('>', i + 1)
            name = pattern[i+1:j]
            names.append(name)
            regex += '([^/]+)'
            i = j + 1
        else:
            regex += re.escape(pattern[i])
            i += 1
    regex += '$'
    return re.compile(regex), names

def route(pattern):
    def decorator(func):
        regex, names = _compile_pattern(pattern)
        _routes.append((regex, names, func))
        return func
    return decorator

def render_template(name, **ctx):
    tpl = templates.get(name, "")
    def repl(m):
        key = m.group(1).strip()
        return str(ctx.get(key, ""))
    return re.sub(r'\{\{\s*(\w+)\s*\}\}', repl, tpl)

@route('/hello/<username>')
def hello(username):
    return render_template('hello.html', username=username)

def handle_request(path):
    for regex, names, func in _routes:
        m = regex.match(path)
        if m:
            args = [m.group(i+1) for i in range(len(names))]
            return func(*args)
    return "404 Not Found"

if __name__ == '__main__':
    tests = ["Alice", "Bob", "Carol_123", "Dora", "Eve"]
    for t in tests:
        print(handle_request(f"/hello/{t}"))