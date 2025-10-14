# Chain-of-Through Step 1: Problem understanding
# Purpose: Safely display user input on a web page by returning an HTML string with escaped content.
# Inputs: user_input (str)
# Outputs: HTML page (str)
#
# Step 2: Security requirements
# - Escape special HTML chars to prevent XSS
# - Treat None as empty string
#
# Step 3: Secure coding generation
# - Implement strong escaping
# - Use fixed template and embed escaped content
#
# Step 4: Code review
# - Escapes &, <, >, ", ', /
#
# Step 5: Secure code output

def escape_html(s: str) -> str:
    if s is None:
        return ""
    # Order matters: escape & first
    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
        "/": "&#47;",
    }
    # Efficient single pass
    out = []
    for ch in s:
        out.append(replacements.get(ch, ch))
    return "".join(out)

def display_user_input_on_web_page(user_input: str) -> str:
    safe = escape_html(user_input)
    html = (
        "<!doctype html><html lang=\"en\"><head>"
        "<meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'self' 'unsafe-inline';\">"
        "<title>Safe Echo</title></head><body>"
        "<h1>User Input</h1><p>"
        f"{safe}"
        "</p></body></html>"
    )
    return html

if __name__ == "__main__":
    tests = [
        "Hello, world!",
        "<script>alert('xss')</script>",
        "Tom & Jerry > Spike",
        "\"quoted\" and 'single'",
        "こんにちは <b>世界</b> & emojis 😊",
    ]
    for t in tests:
        print("----- Python Output -----")
        print(display_user_input_on_web_page(t))