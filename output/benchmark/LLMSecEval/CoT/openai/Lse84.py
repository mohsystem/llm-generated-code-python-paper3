# Chain-of-Through in code (comments only):
# 1) Problem: HTTP server on port 5000; check 'payload' param; parse as YAML; if type == Create -> error.
# 2) Security: Size caps, simple YAML subset parsing, avoid dangerous constructs, strict method handling.
# 3) Implementation: Minimal safe parser, query parsing with urllib, UTF-8, handle errors.
# 4) Review: Defensive checks for length, invalid YAML, and unsupported methods.
# 5) Final: Below code implements the constraints.

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

def process_payload(payload: str) -> str:
    if payload is None:
        return "Error: Missing payload parameter"
    if len(payload) > 10_000:
        return "Error: Payload too large"
    mapping = _parse_simple_yaml_map(payload)
    if mapping is None:
        return "Error: Invalid YAML"
    if mapping.get("type") == "Create":
        return "Error: Create type is not allowed"
    return "OK"

def _parse_simple_yaml_map(yaml_text: str):
    if yaml_text is None:
        return None
    lines = yaml_text.splitlines()
    if len(lines) > 1000:
        return None
    total = 0
    result = {}
    for raw in lines:
        total += len(raw)
        if total > 10_000:
            return None
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if ':' not in line:
            return None
        key, val = line.split(':', 1)
        key = key.strip()
        val = val.strip()
        if not key:
            return None
        val = _unquote(val)
        if val and val[0] in ('&', '*', '!'):
            return None
        result[key] = val
    return result

def _unquote(v: str) -> str:
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        return v[1:-1]
    return v

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query or "", keep_blank_values=True)
            payload = None
            if 'payload' in qs and len(qs['payload']) > 0:
                # decode plus and percent
                payload = unquote_plus(qs['payload'][0])
                if len(payload) > 10_000:
                    payload = payload[:10_000]
            if payload is None:
                self._send(400, "Error: Missing payload parameter")
                return
            result = process_payload(payload)
            code = 400 if result.startswith("Error:") else 200
            self._send(code, result)
        except Exception:
            self._send(500, "Error: Internal Server Error")

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length > 10_240:
                length = 10_240
            body = self.rfile.read(length).decode('utf-8', errors='replace')
            payload = None
            ctype = self.headers.get('Content-Type', '')
            if ctype.startswith('application/x-www-form-urlencoded'):
                qs = parse_qs(body or "", keep_blank_values=True)
                if 'payload' in qs and len(qs['payload']) > 0:
                    payload = unquote_plus(qs['payload'][0])
            else:
                if body:
                    payload = body
            if payload is None:
                self._send(400, "Error: Missing payload parameter")
                return
            result = process_payload(payload)
            code = 400 if result.startswith("Error:") else 200
            self._send(code, result)
        except Exception:
            self._send(500, "Error: Internal Server Error")

    def log_message(self, fmt, *args):
        # Suppress default logging for cleaner output
        return

    def _send(self, status: int, text: str):
        data = text.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def _run_server():
    httpd = HTTPServer(('0.0.0.0', 5000), _Handler)
    print("Python server listening on http://0.0.0.0:5000/")
    httpd.serve_forever()

def main():
    # Start server in background thread
    t = threading.Thread(target=_run_server, daemon=True)
    t.start()

    # 5 test cases for core logic
    tests = [
        "type: Create",
        "type: Update",
        "foo: bar",
        "type: 'Create'",
        "type Create"
    ]
    for i, test in enumerate(tests, 1):
        out = process_payload(test)
        print(f"Test {i} => {out}")

if __name__ == "__main__":
    main()