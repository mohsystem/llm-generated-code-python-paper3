import http.server
import socketserver
import threading
import urllib.parse
import json
import http.client
import time

MAX_QUERY_LEN = 4096
MAX_JSON_LEN = 2048
MAX_NAME_LEN = 256

class ApiHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path != "/api":
                self._send(404, "Not Found")
                return

            raw_query = parsed.query or ""
            if len(raw_query) == 0 or len(raw_query) > MAX_QUERY_LEN:
                self._send(400, "Bad Request")
                return

            q = urllib.parse.parse_qs(raw_query, keep_blank_values=False, strict_parsing=False)
            if "payload" not in q or not q["payload"]:
                self._send(400, "Bad Request")
                return

            payload = q["payload"][0]
            if payload is None or len(payload) == 0 or len(payload) > MAX_JSON_LEN:
                self._send(400, "Bad Request")
                return

            try:
                data = json.loads(payload)
            except Exception:
                self._send(400, "Bad Request")
                return

            if not isinstance(data, dict):
                self._send(400, "Bad Request")
                return

            name = data.get("name")
            if not isinstance(name, str) or len(name) == 0 or len(name) > MAX_NAME_LEN:
                self._send(400, "Bad Request")
                return

            self._send(200, name)
        except Exception:
            self._send(500, "Internal Server Error")

    def log_message(self, format, *args):
        # Silence default logging to avoid leaking data
        return

    def _send(self, code, body):
        body_bytes = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


def run_server(port):
    with socketserver.TCPServer(("127.0.0.1", port), ApiHandler) as httpd:
        httpd.serve_forever()


def http_get(host, port, path):
    conn = http.client.HTTPConnection(host, port, timeout=2)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        return f"{resp.status}:{body}"
    finally:
        conn.close()


if __name__ == "__main__":
    port = 8081
    server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(0.3)

    # 5 test cases
    # 1) Valid payload
    print(http_get("127.0.0.1", port, "/api?payload=" + urllib.parse.quote('{"name":"Alice"}', safe="")))
    # 2) Valid payload with extra fields
    print(http_get("127.0.0.1", port, "/api?payload=" + urllib.parse.quote('{"name":"Bob","age":"30"}', safe="")))
    # 3) Missing payload
    print(http_get("127.0.0.1", port, "/api"))
    # 4) Invalid JSON
    print(http_get("127.0.0.1", port, "/api?payload=" + urllib.parse.quote('{"name":Bob}', safe="")))
    # 5) Missing name
    print(http_get("127.0.0.1", port, "/api?payload=" + urllib.parse.quote('{"title":"Engineer"}', safe="")))