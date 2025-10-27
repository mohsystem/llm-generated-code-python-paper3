import http.server
import threading
import urllib.parse
import http.client
import time

PORT = 5000
MAX_INPUT_SIZE = 65536

def parse_query(q: str) -> dict:
    res = {}
    if not q:
        return res
    for k, v in urllib.parse.parse_qs(q, keep_blank_values=True, strict_parsing=False).items():
        if not k or len(k) > 100:
            continue
        res[k] = v[0] if v else ""
    return res

def parse_simple_yaml(src: str) -> dict:
    if src is None:
        raise ValueError("null")
    if len(src) > MAX_INPUT_SIZE:
        raise ValueError("too large")
    out = {}
    lines = src.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    count = 0
    for line in lines:
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        if ":" not in t:
            raise ValueError("bad line")
        key, val = t.split(":", 1)
        key = key.strip()
        val = val.strip()
        if not key or len(key) > 64 or not all(c.isalnum() or c == "_" for c in key):
            raise ValueError("bad key")
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            if len(val) >= 2:
                val = val[1:-1]
        if len(val) > 4096:
            raise ValueError("value too long")
        out[key] = val
        count += 1
        if count > 64:
            raise ValueError("too many keys")
    if not out:
        raise ValueError("empty mapping")
    return out

def process_request(params: dict) -> (int, str):
    payload = params.get("payload")
    if payload is None:
        return 400, "Error: missing payload parameter"
    if len(payload) > MAX_INPUT_SIZE:
        return 413, "Error: payload too large"
    try:
        ymap = parse_simple_yaml(payload)
    except Exception:
        return 400, "Error: invalid payload format"
    if ymap.get("type") == "Create":
        return 400, "Error: operation not allowed"
    return 200, "OK"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urllib.parse.urlsplit(self.path)
            params = parse_query(parsed.query)
            status, body = process_request(params)
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body) + 1))
            self.end_headers()
            self.wfile.write((body + "\n").encode("utf-8"))
        except Exception:
            self.send_error(500, "Internal Server Error")

    def do_POST(self):
        try:
            parsed = urllib.parse.urlsplit(self.path)
            params = parse_query(parsed.query)
            clen = 0
            if "Content-Length" in self.headers:
                try:
                    clen = int(self.headers.get("Content-Length", "0").strip())
                except Exception:
                    clen = 0
            if clen > MAX_INPUT_SIZE:
                status, body = 413, "Error: payload too large"
            else:
                body = self.rfile.read(clen) if clen > 0 else b""
                ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if ctype == "application/x-www-form-urlencoded":
                    params.update(parse_query(body.decode("utf-8", errors="replace")))
                elif ctype == "text/plain":
                    params.setdefault("payload", body.decode("utf-8", errors="replace"))
                status, body = process_request(params)
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body) + 1))
            self.end_headers()
            self.wfile.write((body + "\n").encode("utf-8"))
        except Exception:
            self.send_error(500, "Internal Server Error")

    def log_message(self, fmt, *args):
        return  # quiet

def run_server(server):
    server.serve_forever(poll_interval=0.2)

if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    t = threading.Thread(target=run_server, args=(server,), daemon=True)
    t.start()
    time.sleep(0.3)

    def send(method, path, body=None, content_type=None):
        conn = http.client.HTTPConnection("localhost", PORT, timeout=3)
        headers = {}
        if body is not None:
            headers["Content-Length"] = str(len(body.encode("utf-8")))
        if content_type:
            headers["Content-Type"] = content_type
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        print(f"[{method} {path}] -> HTTP {resp.status} | Body: {data.strip()[:120]}")
        conn.close()

    # 1) Missing payload
    send("GET", "/")

    # 2) payload with type: Create
    y1 = "type: Create\nuser: alice"
    send("GET", "/?payload=" + urllib.parse.quote(y1))

    # 3) payload with type: Update
    y2 = "type: Update\nid: 42"
    send("GET", "/?payload=" + urllib.parse.quote(y2))

    # 4) invalid YAML
    y3 = "type Create\n"
    send("GET", "/?payload=" + urllib.parse.quote(y3))

    # 5) too large payload via POST
    big = "A" * 70000
    y4 = "type: Update\npad: " + big
    send("POST", "/", body="payload=" + urllib.parse.quote(y4), content_type="application/x-www-form-urlencoded")

    server.shutdown()
    t.join(timeout=2)