import http.server
import socketserver
from urllib.parse import urlparse, parse_qs, unquote_plus
import json
import threading

# Parse payload JSON into a dictionary
def parse_payload_to_dict(payload: str) -> dict:
    if payload is None:
        return {}
    try:
        return json.loads(payload)
    except Exception:
        # Fallback minimal parser for flat JSON with string/number/bool/null values
        s = payload.strip()
        if s.startswith("{"):
            s = s[1:]
        if s.endswith("}"):
            s = s[:-1]
        result = {}
        cur = ""
        in_quotes = False
        esc = False
        parts = []
        for ch in s:
            if in_quotes:
                cur += ch
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == "\"":
                    in_quotes = False
            else:
                if ch == "\"":
                    in_quotes = True
                    cur += ch
                elif ch == ",":
                    parts.append(cur)
                    cur = ""
                else:
                    cur += ch
        if cur:
            parts.append(cur)
        for part in parts:
            p = part.strip()
            if not p:
                continue
            # split on first colon not in quotes
            in_quotes = False
            esc = False
            idx = -1
            for i, c in enumerate(p):
                if in_quotes:
                    if esc:
                        esc = False
                    elif c == "\\":
                        esc = True
                    elif c == "\"":
                        in_quotes = False
                else:
                    if c == "\"":
                        in_quotes = True
                    elif c == ":":
                        idx = i
                        break
            if idx < 0:
                continue
            k = p[:idx].strip()
            v = p[idx+1:].strip()
            if k.startswith("\"") and k.endswith("\""):
                k = k[1:-1]
            if v.startswith("\"") and v.endswith("\""):
                # unescape basic sequences
                try:
                    v = bytes(v[1:-1], "utf-8").decode("unicode_escape")
                except Exception:
                    v = v[1:-1]
            result[k] = v
        return result

# Get "name" from payload JSON
def get_name_from_payload(payload: str) -> str:
    d = parse_payload_to_dict(payload)
    return str(d.get("name", "")) if isinstance(d, dict) else ""

class ApiHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return
        qs = parse_qs(parsed.query)
        payload_vals = qs.get("payload", [])
        if not payload_vals:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing payload parameter")
            return
        payload = payload_vals[0]
        payload = unquote_plus(payload)
        name = get_name_from_payload(payload)
        resp = name.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

def run_server():
    with socketserver.TCPServer(("", 8080), ApiHandler) as httpd:
        # print("Python server running on http://localhost:8080/api?payload=%7B%22name%22%3A%22World%22%7D")
        httpd.serve_forever()

if __name__ == "__main__":
    # 5 test cases
    tests = [
        '{"name":"Alice"}',
        '{"name":"Bob","age":30}',
        '{"age":22,"name":"Carol"}',
        '{"name":"D\\\"E"}',
        '{"name":"Eve Adams","city":"NY"}',
    ]
    for t in tests:
        print(get_name_from_payload(t))
    # Start server in main thread
    run_server()