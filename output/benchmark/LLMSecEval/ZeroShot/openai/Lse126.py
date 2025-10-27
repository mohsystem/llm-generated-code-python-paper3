import io
import html
import sys
import unicodedata

class Lse126:
    @staticmethod
    def http_hello_page(request_body):
        username = Lse126._sanitize_username(request_body)
        safe_name = Lse126._escape_html(username)

        outputbuf = (
            "<!doctype html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<title>Hello</title>\n"
            "</head>\n"
            "<body>\n"
            f"<h1>Hello, {safe_name}!</h1>\n"
            "</body>\n"
            "</html>\n"
        )

        # Simulate writing to response stream
        response_stream = io.BytesIO()
        try:
            response_stream.write(outputbuf.encode("utf-8"))
            response_stream.flush()
            data = response_stream.getvalue()
        finally:
            response_stream.close()

        return data.decode("utf-8", errors="strict")

    @staticmethod
    def _sanitize_username(username):
        if username is None:
            username = "Guest"
        else:
            try:
                username = str(username)
            except Exception:
                username = "Guest"
        # Limit to 256 characters (code points)
        username = username[:256]
        # Remove control characters
        cleaned_chars = []
        for ch in username:
            cat = unicodedata.category(ch)
            if not cat.startswith("C"):  # Exclude control/surrogate/unassigned
                cleaned_chars.append(ch)
        return "".join(cleaned_chars)

    @staticmethod
    def _escape_html(s):
        escaped = html.escape(s, quote=True)
        escaped = escaped.replace("'", "&#x27;")
        return escaped

if __name__ == "__main__":
    tests = [
        "Alice",
        "<script>alert(1)</script>",
        "Bob_the_Builder_" * 30,
        None,
        "Eve\u0007\u0008\n\r\t"
    ]
    for i, t in enumerate(tests, 1):
        res = Lse126.http_hello_page(t)
        sys.stdout.write(f"Test {i}:\n{res}\n\n")