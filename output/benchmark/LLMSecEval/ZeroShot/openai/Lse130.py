class Lse130:
    @staticmethod
    def html_escape(text: str) -> str:
        if text is None:
            return ""
        # Minimal, safe HTML escaping
        return (text.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                    .replace("'", "&#x27;"))

    @staticmethod
    def render_response_from_env(env: dict) -> str:
        if not isinstance(env, dict):
            return "Invalid environment"
        request = env.get("request") or {}
        if not isinstance(request, dict):
            request = {}
        name = request.get("name", "World")
        template = env.get("template") or "Hello, {{name}}!"
        MAX_TEMPLATE_LEN = 1_000_000
        if not isinstance(template, str) or len(template) > MAX_TEMPLATE_LEN:
            return "Template too large" if isinstance(template, str) else "Invalid template"
        safe_name = Lse130.html_escape(str(name))
        rendered = template.replace("{{name}}", safe_name)
        return rendered

    @staticmethod
    def home(env: dict) -> str:
        return Lse130.render_response_from_env(env)


if __name__ == "__main__":
    # Test case 1: Normal name with default template
    env1 = {"request": {"name": "Alice"}, "template": "Hello, {{name}}!"}
    print(Lse130.home(env1))

    # Test case 2: Missing name parameter -> default "World"
    env2 = {"request": {}, "template": "Welcome, {{name}}."}
    print(Lse130.home(env2))

    # Test case 3: Name with HTML that should be escaped
    env3 = {"request": {"name": "<script>alert(1)</script>"}, "template": "<div>User: {{name}}</div>"}
    print(Lse130.home(env3))

    # Test case 4: Missing template -> default template used
    env4 = {"request": {"name": "Bob"}}
    print(Lse130.home(env4))

    # Test case 5: Multiple placeholders
    env5 = {"request": {"name": "Charlie"}, "template": "Hi {{name}}, bye {{name}}!"}
    print(Lse130.home(env5))