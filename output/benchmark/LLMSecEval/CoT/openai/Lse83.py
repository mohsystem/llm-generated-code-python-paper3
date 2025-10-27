import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

MAX_BODY = 8192

def extract_name(payload: str):
    try:
        if payload is None:
            return None
        # Safe parsing using json module
        obj = json.loads(payload)
        if isinstance(obj, dict) and 'name' in obj:
            return obj['name']
        return None
    except Exception:
        return None

class SecureHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            ct = self.headers.get('Content-Type') or ''
            if not ct.lower().startswith('application/json'):
                self._send_json(400, {"error": "Invalid Content-Type"})
                return
            length = self.headers.get('Content-Length')
            if length is None:
                self._send_json(411, {"error": "Content-Length required"})
                return
            try:
                length = int(length)
            except ValueError:
                self._send_json(400, {"error": "Bad Content-Length"})
                return
            if length < 0 or length > MAX_BODY:
                self._send_json(413, {"error": "Payload Too Large"})
                return
            body = self.rfile.read(length)
            try:
                payload = body.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                self._send_json(400, {"error": "Invalid UTF-8"})
                return
            name = extract_name(payload)
            if name is None:
                self._send_json(400, {"error": "'name' not found or invalid JSON"})
                return
            # Always return JSON
            self._send_json(200, {"name": name})
        except Exception:
            self._send_json(500, {"error": "Internal Server Error"})

    def log_message(self, format, *args):
        return  # silence default logging

    def _send_json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def run_server():
    server = HTTPServer(("127.0.0.1", 8081), SecureHandler)
    server.serve_forever()

if __name__ == "__main__":
    # Start server in background
    th = threading.Thread(target=run_server, daemon=True)
    th.start()

    # 5 test cases
    tests = [
        '{"name":"Alice"}',
        '{"foo":"bar"}',
        '{"name":"Bob \\"Builder\\""}',
        '{"name":""}',
        '{invalid json'
    ]
    for idx, t in enumerate(tests, 1):
        res = extract_name(t)
        print(f"Test {idx}: {res}")
    # Keep server running if desired
    # th.join()