import html
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

# In-memory "DB"
_DB_LOCK = threading.Lock()
_DB = []
_MAX_USERNAME = 50
_MAX_MESSAGE = 500
_MAX_BODY = 4096

def insert_user_message_in_db(username: str, message: str) -> bool:
    if username is None or message is None:
        return False
    u = username.strip()
    m = message.strip()
    if not u or not m:
        return False
    if len(u) > _MAX_USERNAME or len(m) > _MAX_MESSAGE:
        return False
    with _DB_LOCK:
        _DB.append((u, m))
    return True

def render_messages_html() -> bytes:
    with _DB_LOCK:
        snapshot = list(_DB)
    parts = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'>")
    parts.append("<meta http-equiv='Content-Security-Policy' content=\"default-src 'self'; style-src 'self' 'unsafe-inline'\">")
    parts.append("<title>Messages</title></head><body>")
    parts.append("<h1>Messages</h1>")
    parts.append("<form method='POST' action='/post'>")
    parts.append(f"<label>Username: <input name='username' maxlength='{_MAX_USERNAME}'></label><br>")
    parts.append(f"<label>Message: <input name='message' maxlength='{_MAX_MESSAGE}'></label><br>")
    parts.append("<button type='submit'>Post</button></form><hr><ul>")
    for u, m in snapshot:
        parts.append(f"<li><strong>{html.escape(u)}</strong>: {html.escape(m)}</li>")
    parts.append("</ul></body></html>")
    return "".join(parts).encode("utf-8")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = render_messages_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/post":
            self.send_error(404)
            return
        ctype = self.headers.get("Content-Type", "")
        if not ctype.lower().startswith("application/x-www-form-urlencoded"):
            self.send_error(415)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > _MAX_BODY:
            self.send_error(413)
            return
        body = self.rfile.read(length).decode("utf-8", errors="strict")
        data = parse_qs(body, keep_blank_values=True, strict_parsing=False)
        username = data.get("username", [""])[0]
        message = data.get("message", [""])[0]
        insert_user_message_in_db(username, message)
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

def main():
    # 5 test cases (pre-populate DB)
    insert_user_message_in_db("alice", "Hello from Python!")
    insert_user_message_in_db("bob", "Security first.")
    insert_user_message_in_db("charlie", "Avoid XSS <script>")
    insert_user_message_in_db("dora", "Use limits & escaping.")
    insert_user_message_in_db("eve", "Stay kind.")

    server = HTTPServer(("0.0.0.0", 8080), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()