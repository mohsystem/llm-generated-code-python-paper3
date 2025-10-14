class Task120:
    @staticmethod
    def _escape_html(s: str) -> str:
        if s is None:
            s = ""
        # Manual escape to include slash as well.
        mapping = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
        }
        # Build efficiently
        out_chars = []
        for ch in s:
            out_chars.append(mapping.get(ch, ch))
        return ''.join(out_chars)

    @staticmethod
    def display_user_input(user_input: str) -> str:
        safe = Task120._escape_html(user_input)
        parts = [
            "<!DOCTYPE html>",
            "<html lang=\"en\">",
            "<head>",
            "<meta charset=\"UTF-8\">",
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none';\">",
            "<title>Safe Echo</title>",
            "</head>",
            "<body>",
            "<h1>Echo</h1>",
            "<pre>",
            safe,
            "</pre>",
            "</body>",
            "</html>"
        ]
        return "\n".join(parts)

if __name__ == "__main__":
    tests = [
        "Hello, world!",
        "<script>alert('XSS');</script>",
        "Tom & Jerry > Mickey & Minnie",
        "\"Quotes\" and 'single quotes' and /slashes/",
        "Unicode: Привет, 你好, مرحبا, 😀",
    ]
    for i, t in enumerate(tests, 1):
        print(f"----- Test {i} -----")
        print(Task120.display_user_input(t))