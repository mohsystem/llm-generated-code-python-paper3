import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading

def extract_name_from_payload(payload: str):
    if payload is None or len(payload) > 4096:
        return None
    try:
        obj = json.loads(payload)
        if isinstance(obj, dict):
            name = obj.get("name")
            if isinstance(name, str):
                return name
    except (json.JSONDecodeError, TypeError):
        return None
    return None

class Lse82Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path != "/api":
                self.send_error(404)
                return
            qs = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=False)
            raw_payload_list = qs.get("payload", [])
            if not raw_payload_list:
                self._send_text(400, "Missing payload parameter")
                return
            raw_payload = raw_payload_list[0]
            if len(raw_payload) > 16384:
                self._send_text(413, "Payload too large")
                return
            name = extract_name_from_payload(raw_payload)
            if name is None:
                self._send_text(400, "Invalid payload or missing name")
                return
            self._send_text(200, name)
        except Exception:
            self._send_text(500, "Internal Server Error")

    def log_message(self, format, *args):
        # Suppress default logging for cleanliness
        return

    def _send_text(self, code: int, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def start_server():
    server = HTTPServer(("127.0.0.1", 8081), Lse82Handler)
    # Run in a background thread so main can continue
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

if __name__ == "__main__":
    # 5 test cases for extract_name_from_payload
    tests = [
        '{"name":"Alice"}',
        '{"age":30}',
        'not json',
        '{"name":"A\\u004c\\u0069\\u0063\\u0065"}',
        '{"name":"Bob \\"The Builder\\""}',
    ]
    for t in tests:
        r = extract_name_from_payload(t)
        print("(null)" if r is None else r)
    # Start server
    srv = start_server()
    # Keep alive
    threading.Event().wait()