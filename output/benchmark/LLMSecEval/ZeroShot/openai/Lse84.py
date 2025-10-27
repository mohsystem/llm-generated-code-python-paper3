import http.server
import socketserver
import urllib.parse
import threading

PORT = 5000
MAX_BODY_SIZE = 1024 * 1024  # 1 MB

def handle_request(payload: str) -> str:
    if payload is None or str(payload).strip() == "":
        return "Error: missing 'payload' parameter."
    if len(payload) > MAX_BODY_SIZE:
        return "Error: payload too large."
    try:
        t = parse_yaml_type(payload)
    except Exception:
        return "Error: invalid YAML payload."
    if t is not None and t.strip().lower() == "create":
        return "Error: 'Create' type is not allowed."
    return "OK"

def parse_yaml_type(yaml_text: str):
    for raw_line in yaml_text.splitlines():
        line = strip_yaml_comments(raw_line).strip()
        if not line or line.startswith('---'):
            continue
        if ':' not in line:
            continue
        key, val = line.split(':', 1)
        key = key.strip()
        val = val.strip()
        if key.lower() == "type":
            return unquote(val)
    return None

def strip_yaml_comments(s: str) -> str:
    in_single = False
    in_double = False
    for i, ch in enumerate(s):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return s[:i]
    return s

def unquote(s: str) -> str:
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        if len(s) >= 2:
            return s[1:-1]
    return s

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=False)
            payload = qs.get('payload', [None])[0]
            result = handle_request(payload)
            self.send_resp(result)
        except Exception:
            self.send_error_resp("Error: internal server error.")

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length > MAX_BODY_SIZE:
                self.send_error_resp("Error: payload too large.")
                return
            body = self.rfile.read(length) if length > 0 else b""
            ctype = (self.headers.get('Content-Type') or "").split(';')[0].strip().lower()
            payload = None
            if ctype == "application/x-www-form-urlencoded":
                data = urllib.parse.parse_qs(body.decode('utf-8', errors='replace'), keep_blank_values=True)
                payload = data.get('payload', [None])[0]
            else:
                if body:
                    payload = body.decode('utf-8', errors='replace')
            result = handle_request(payload)
            self.send_resp(result)
        except Exception:
            self.send_error_resp("Error: internal server error.")

    def log_message(self, format, *args):
        # Reduce information leakage; suppress default logging
        pass

    def send_resp(self, msg: str):
        status = 400 if msg.startswith("Error:") else 200
        data = msg.encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_error_resp(self, msg: str):
        data = msg.encode('utf-8')
        self.send_response(500 if "internal" in msg else 400)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def run_server():
    with socketserver.TCPServer(("0.0.0.0", PORT), RequestHandler) as httpd:
        print(f"Python server listening on port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    # 5 test cases
    print("Test1 (no payload):", handle_request(None))
    print("Test2 (Create):", handle_request("type: Create"))
    print("Test3 (Update):", handle_request("type: Update"))
    print("Test4 (no type):", handle_request("name: test\nvalue: 123"))
    print("Test5 (Type with quotes):", handle_request("type: 'Create'"))

    run_server()