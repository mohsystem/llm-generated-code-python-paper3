import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

def handle_payload(payload: str) -> str:
    if payload is None or payload.strip() == "":
        return "Error: missing payload parameter"
    t = yaml_get_type(payload)
    if t is not None and t == "Create":
        return "Error: payload type Create is not allowed"
    return "OK"

def process_params(params: dict) -> str:
    payload = params.get("payload")
    if payload is None:
        return "Error: missing payload parameter"
    if isinstance(payload, list):
        payload = payload[0] if payload else None
    return handle_payload(payload)

def yaml_get_type(payload: str) -> str | None:
    if payload is None:
        return None
    for raw in payload.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        if key == "type":
            return val
    return None

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        # decode values
        decoded = {}
        for k, v in qs.items():
            dk = unquote_plus(k)
            dv = [unquote_plus(x) for x in v]
            decoded[dk] = dv if len(dv) > 1 else dv
        result = process_params(decoded)
        body = result.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run_server():
    httpd = HTTPServer(("0.0.0.0", 5000), Handler)
    httpd.serve_forever()

if __name__ == "__main__":
    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    # 5 test cases
    print(handle_payload(None))                 # Missing -> error
    print(handle_payload("type: Create"))       # Create -> error
    print(handle_payload("type: Update"))       # OK
    print(handle_payload("name: x"))            # OK (no type)
    print(handle_payload("TYPE: Create"))       # OK (case-sensitive key)

    t.join()