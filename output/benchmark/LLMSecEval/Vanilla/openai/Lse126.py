def http_hello_page(username):
    name = "Guest" if not username else _escape_html(str(username))
    return (
        "<!DOCTYPE html>\n"
        "<html><head><meta charset=\"UTF-8\"><title>Hello</title></head><body>"
        f"<h1>Hello, {name}!</h1>"
        "<p>Welcome to the hello page.</p>"
        "</body></html>"
    )

def _escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )

if __name__ == "__main__":
    tests = ["Alice", "Bob & Co", "<script>", "", None]
    for t in tests:
        print("=== Test ===")
        print(http_hello_page(t))