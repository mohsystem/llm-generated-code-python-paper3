from typing import Dict, List, Optional
import html


class Message:
    def __init__(self, username: str, message: str):
        self.username = username
        self.message = message


class InMemoryDB:
    def __init__(self, max_messages: int = 1000):
        self._msgs: List[Message] = []
        self._max = max(1, int(max_messages))

    def insert_user_message_in_db(self, username: Optional[str], message: Optional[str]) -> bool:
        if username is None or message is None:
            return False
        if not self._valid_username(username):
            return False
        if not self._valid_message(message):
            return False
        if len(self._msgs) >= self._max:
            self._msgs.pop(0)
        self._msgs.append(Message(username, message))
        return True

    def get_all(self) -> List[Message]:
        return list(self._msgs)

    @staticmethod
    def _valid_username(u: str) -> bool:
        if not (1 <= len(u) <= 20):
            return False
        for ch in u:
            if not (ch.isalnum() or ch == "_"):
                return False
        return True

    @staticmethod
    def _valid_message(m: str) -> bool:
        # Count of code points; Python len is OK for BMP and general usage
        return 1 <= len(m) <= 280


class Request:
    def __init__(self, method: str, path: str, form: Optional[Dict[str, str]] = None):
        self.method = method
        self.path = path
        self.form = dict(form) if form else {}


class Response:
    def __init__(self, status_code: int, headers: Optional[Dict[str, str]] = None, body: bytes = b""):
        self.status_code = status_code
        self.headers = dict(headers) if headers else {}
        self.body = body

    def __str__(self) -> str:
        lines = [f"Status: {self.status_code}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(self.body.decode("utf-8", errors="replace"))
        return "\n".join(lines)


class App:
    def __init__(self, db: InMemoryDB):
        self.db = db

    def handle(self, req: Request) -> Response:
        if not req or not req.method or not req.path:
            return self._text(400, "Bad Request")
        if req.method == "GET" and req.path == "/":
            return self._handle_root()
        if req.method == "POST" and req.path == "/post":
            return self._handle_post(req)
        return self._text(404, "Not Found")

    def _handle_root(self) -> Response:
        items = []
        for m in self.db.get_all():
            items.append(f"<li><strong>{html.escape(m.username)}</strong>: {html.escape(m.message)}</li>")
        body = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Messages</title></head>
<body>
<h1>Message Board</h1>
<form method="POST" action="/post" onsubmit="return /^[A-Za-z0-9_]{{1,20}}$/.test(this.username.value);">
Username: <input name="username" maxlength="20" required pattern="[A-Za-z0-9_]+">
Message: <input name="message" maxlength="280" required>
<button type="submit">Post</button>
</form>
<h2>Messages</h2>
<ul>
{''.join(items)}
</ul>
</body></html>"""
        return self._html(200, body)

    def _handle_post(self, req: Request) -> Response:
        username = (req.form.get("username") or "").strip()
        message = (req.form.get("message") or "").strip()
        if not self.db.insert_user_message_in_db(username, message):
            return self._text(400, "Invalid input")
        return Response(303, {"Location": "/"}, b"")

    @staticmethod
    def _text(code: int, body: str) -> Response:
        return Response(code, {"Content-Type": "text/plain; charset=utf-8"}, body.encode("utf-8"))

    @staticmethod
    def _html(code: int, body: str) -> Response:
        return Response(code, {"Content-Type": "text/html; charset=utf-8"}, body.encode("utf-8"))


def run_tests():
    db = InMemoryDB(1000)
    app = App(db)

    # Test 1: Valid post
    print("Test 1: Valid POST /post")
    res = app.handle(Request("POST", "/post", {"username": "alice", "message": "Hello, world!"}))
    print(res)
    print("GET / after Test 1")
    print(app.handle(Request("GET", "/", {})))

    # Test 2: Invalid username
    print("Test 2: Invalid username")
    res = app.handle(Request("POST", "/post", {"username": "bob!", "message": "Should fail"}))
    print(res)

    # Test 3: Too long message
    print("Test 3: Too long message")
    res = app.handle(Request("POST", "/post", {"username": "charlie", "message": "x" * 281}))
    print(res)

    # Test 4: XSS attempt
    print("Test 4: XSS attempt")
    res = app.handle(Request("POST", "/post", {"username": "dana", "message": "<script>alert(1)</script> ok"}))
    print(res)
    print("GET / after Test 4")
    print(app.handle(Request("GET", "/", {})))

    # Test 5: Another valid
    print("Test 5: Another valid")
    res = app.handle(Request("POST", "/post", {"username": "eve_123", "message": "Good day!"}))
    print(res)
    print("GET / after Test 5")
    print(app.handle(Request("GET", "/", {})))


if __name__ == "__main__":
    run_tests()