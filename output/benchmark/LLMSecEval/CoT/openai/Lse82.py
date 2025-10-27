# Steps applied (high-level):
# 1) Build a minimal web app with /api route reading ?payload=..., parse JSON to dict, return dict['name'].
# 2) Security: enforce size limit, safe JSON decode, validate key presence/type, error handling.
# 3) Implement with built-in libraries only, no unsafe eval.
# 4) Checked for input bounds and errors.
# 5) Final secure code.

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

MAX_PAYLOAD_LENGTH = 2048

def get_name_from_payload(payload: str) -> str:
    if payload is None:
        raise ValueError("Missing payload")
    if len(payload) > MAX_PAYLOAD_LENGTH:
        raise ValueError("Payload too large")
    try:
        obj = json.loads(payload)
    except Exception:
        raise ValueError("Invalid JSON")
    if not isinstance(obj, dict):
        raise ValueError("JSON must be an object")
    name = obj.get("name", None)
    if not isinstance(name, str):
        raise ValueError("Invalid or missing 'name'")
    return name

class ApiHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path != "/api":
                self.send_resp(404, "Not Found")
                return
            qs = parse_qs(parsed.query, keep_blank_values=True)
            payload_vals = qs.get("payload", [])
            if not payload_vals:
                self.send_resp(400, "Missing 'payload' parameter")
                return
            payload_raw = payload_vals[0]
            # Handle decoding of '+' and percent-encodings
            payload = unquote_plus(payload_raw)
            if len(payload) > MAX_PAYLOAD_LENGTH:
                self.send_resp(413, "Payload too large")
                return
            try:
                name = get_name_from_payload(payload)
            except ValueError:
                self.send_resp(400, "Invalid or missing 'name'")
                return
            self.send_resp(200, name)
        except Exception:
            self.send_resp(500, "Internal Server Error")

    def log_message(self, format, *args):
        return  # silence default logging

    def send_resp(self, code: int, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def run_server():
    httpd = HTTPServer(("0.0.0.0", 8082), ApiHandler)
    print("Python server listening on http://localhost:8082/api?payload={...}")
    httpd.serve_forever()

if __name__ == "__main__":
    # 5 test cases for core function
    tests = [
        '{"name":"Alice"}',
        '{"name":"Bob","age":"30"}',
        '{"Name":"CaseSensitive"}',
        '{invalid json}',
        '{"name":""}'
    ]
    for i, t in enumerate(tests, 1):
        try:
            res = get_name_from_payload(t)
            print(f"Test {i} OK: '{res}'")
        except Exception as e:
            print(f"Test {i} Error: {e}")
    run_server()