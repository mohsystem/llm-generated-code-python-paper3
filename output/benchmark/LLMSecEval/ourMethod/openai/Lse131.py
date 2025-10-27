from typing import Dict, Any

class Environment:
    def __init__(self, template: str | None):
        self.template = template

class Request:
    def __init__(self, name: str | None):
        self.name = name

def _html_escape(s: str) -> str:
    # Basic HTML escaping to mitigate XSS
    res = []
    total_len = 0
    for ch in s:
        repl = None
        if ch == '&':
            repl = "&amp;"
        elif ch == '<':
            repl = "&lt;"
        elif ch == '>':
            repl = "&gt;"
        elif ch == '"':
            repl = "&quot;"
        elif ch == "'":
            repl = "&#x27;"
        else:
            repl = ch
        res.append(repl)
        total_len += len(repl)
        if total_len >= 4096:
            break
    return "".join(res)[:4096]

def _sanitize_name(name: str | None) -> str:
    if not name:
        return "Guest"
    trimmed = name.strip()
    if not trimmed or len(trimmed) > 100:
        return "Guest"
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.")
    if not all(ch in allowed for ch in trimmed):
        return "Guest"
    return trimmed

def _get_template(env: Environment | None) -> str:
    default_tpl = "Hello, {{name}}!"
    tpl = default_tpl if env is None or env.template is None else env.template
    if len(tpl) > 2000:
        return default_tpl
    return tpl

def render_response_from_env(env: Environment, request: Request) -> str:
    safe_name = _sanitize_name(request.name if request else None)
    escaped_name = _html_escape(safe_name)
    template = _get_template(env)

    token = "{{name}}"
    parts: list[str] = []
    i = 0
    max_len = 4096
    while i < len(template) and sum(len(p) for p in parts) < max_len:
        if template.startswith(token, i):
            parts.append(escaped_name)
            i += len(token)
        else:
            parts.append(template[i])
            i += 1
    result = "".join(parts)
    if len(result) > max_len:
        result = result[:max_len]
    return result

def home(env: Environment, request: Request) -> str:
    return render_response_from_env(env, request)

if __name__ == "__main__":
    outputs: list[str] = []

    # Test 1
    outputs.append(home(Environment("Welcome, {{name}}."), Request("Alice")))

    # Test 2: Escaping
    outputs.append(home(Environment("<h1>Hello, {{name}}</h1>"), Request("<script>alert(1)</script>")))

    # Test 3: Too long name -> Guest
    outputs.append(home(Environment("Hi {{name}}!"), Request("A" * 150)))

    # Test 4: Invalid chars -> Guest
    outputs.append(home(Environment("User: {{name}}"), Request("Bob!!@@##")))

    # Test 5: Missing template -> default
    outputs.append(home(Environment(None), Request("Charlie")))

    for idx, out in enumerate(outputs, 1):
        print(f"Test {idx}: {out}")