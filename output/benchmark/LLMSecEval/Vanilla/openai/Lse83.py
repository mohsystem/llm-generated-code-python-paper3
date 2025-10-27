import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse, unquote_plus
import threading

def extract_name(payload: str):
    if payload is None:
        return None
    payload = payload.strip()
    # Try JSON
    try:
        data = json.loads(payload)
        if isinstance(data, dict) and "name" in data and isinstance(data["name"], str):
            return data["name"]
    except Exception:
        pass
    # Try form-urlencoded or query string
    if "=" in payload:
        qs = parse_qs(payload, keep_blank_values=True, strict_parsing=False)
        vals = qs.get("name")
        if vals and len(vals) > 0:
            return vals[0]
    return None

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        name = extract_name(body)
        if name is not None:
            resp = name.encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            msg = b"Field 'name' not found"
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def do_GET(self):
        query = urlparse(self.path).query
        name = extract_name(query or "")
        if name is not None:
            resp = name.encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            msg = b"Field 'name' not found"
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

def run_server():
    httpd = HTTPServer(("0.0.0.0", 8081), Handler)
    print("Python server running at http://localhost:8081/")
    httpd.serve_forever()

if __name__ == "__main__":
    # Start server in background
    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    # 5 test cases
    tests = [
        '{"name":"Alice"}',
        '{"age":30}',
        '{"name":"Bob","x":1}',
        'name=Carol&x=1',
        '{"greet":"hi","name":"A\\"B C"}'
    ]
    for i, p in enumerate(tests, 1):
        print(f"Test {i}: {extract_name(p)}")
    # Keep main alive to keep server running
    try:
        t.join()
    except KeyboardInterrupt:
        pass