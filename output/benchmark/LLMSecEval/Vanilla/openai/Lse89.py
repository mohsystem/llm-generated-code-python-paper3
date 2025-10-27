import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen
import time
import json

# Function: returns unit price for a product code
def price_for_code(code: str) -> float:
    if code is None:
        return 0.0
    prices = {
        "A100": 10.0,
        "B200": 20.0,
        "C300": 7.5,
        "D400": 15.25,
        "E500": 5.75
    }
    return float(prices.get(code, 0.0))

# Function: returns total price for code and quantity
def total_price(code: str, qty: int) -> float:
    if qty is None or qty < 0:
        qty = 0
    return price_for_code(code) * qty

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/price":
            self.send_response(404)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'{"error":"not found"}')
            return

        q = parse_qs(parsed.query or "")
        code = q.get("code", [""])[0]
        try:
            qty = int(q.get("qty", ["0"])[0])
        except:
            qty = 0
        unit = price_for_code(code)
        total = unit * max(0, qty)
        body = json.dumps({
            "code": code,
            "unitPrice": round(unit, 2),
            "qty": qty,
            "total": round(total, 2)
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Suppress default logging for clarity
        return

def start_server(port: int = 5000) -> HTTPServer:
    srv = HTTPServer(("0.0.0.0", port), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv

def _http_get(url: str) -> str:
    with urlopen(url, timeout=2) as resp:
        return resp.read().decode("utf-8")

if __name__ == "__main__":
    port = 5000
    srv = start_server(port)
    time.sleep(0.2)

    # 5 test cases hitting the endpoint
    base = f"http://127.0.0.1:{port}"
    tests = [
        "/price?code=A100&qty=3",
        "/price?code=B200&qty=2",
        "/price?code=C300&qty=5",
        "/price?code=D400&qty=1",
        "/price?code=Z999&qty=4"
    ]
    for t in tests:
        print("GET", t, "->", _http_get(base + t))

    # Function tests
    print("price_for_code('A100') =", price_for_code("A100"))
    print("total_price('B200', 3) =", total_price("B200", 3))

    # Clean shutdown
    srv.shutdown()
    srv.server_close()