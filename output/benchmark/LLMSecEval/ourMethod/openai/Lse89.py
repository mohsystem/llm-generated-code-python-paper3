import json
import re
import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PRICES = {
    "P100": 10.00,
    "P200": 25.50,
    "P300": 99.99,
    "P400": 5.25,
    "P500": 1.50,
}

CODE_RE = re.compile(r"^[A-Za-z0-9]{1,20}$")

def is_valid_code(code: str) -> bool:
    if code is None:
        return False
    if not CODE_RE.fullmatch(code):
        return False
    return True

def parse_quantity(qty_str: str):
    if qty_str is None:
        return None
    if not qty_str.isdigit():
        return None
    try:
        q = int(qty_str)
    except ValueError:
        return None
    if q < 1 or q > 100000:
        return None
    return q

# Function: return price for a product code, or None if invalid/unknown
def get_price_for_code(code: str):
    if not is_valid_code(code):
        return None
    return PRICES.get(code)

# Function: calculate total for product+qty, or None on invalid input
def calculate_total(code: str, qty: int):
    if not is_valid_code(code):
        return None
    if not isinstance(qty, int) or qty < 1 or qty > 100000:
        return None
    price = PRICES.get(code)
    if price is None:
        return None
    return round(price * qty, 2)

class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class Handler(BaseHTTPRequestHandler):
    server_version = "SecureSimpleHTTP/1.0"

    def log_message(self, fmt, *args):
        # Minimal logging without echoing user-controlled data
        return

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path != "/price":
                self._send_json(404, {"error": "not found"})
                return
            params = parse_qs(parsed.query or "", strict_parsing=False, keep_blank_values=False)
            code_vals = params.get("code", [])
            qty_vals = params.get("qty", [])
            code = code_vals[0] if code_vals else None
            qty_str = qty_vals[0] if qty_vals else None

            if not is_valid_code(code):
                self._send_json(400, {"error": "invalid input"})
                return
            qty = parse_quantity(qty_str)
            if qty is None:
                self._send_json(400, {"error": "invalid input"})
                return
            price = PRICES.get(code)
            if price is None:
                self._send_json(404, {"error": "not found"})
                return
            total = round(price * qty, 2)
            self._send_json(200, {
                "code": code,
                "unitPrice": price,
                "quantity": qty,
                "total": total
            })
        except Exception:
            self._send_json(500, {"error": "server error"})

    def _send_json(self, status: int, obj):
        body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def main():
    # 5 function-level test cases
    print("Test1 total P100 x 3 =", calculate_total("P100", 3))   # 30.0
    print("Test2 total P200 x 2 =", calculate_total("P200", 2))   # 51.0
    print("Test3 price P300 =", get_price_for_code("P300"))       # 99.99
    print("Test4 invalid code ->", get_price_for_code("BAD!"))    # None
    print("Test5 invalid qty ->", calculate_total("P100", 0))     # None

    server = ThreadingHTTPServer(("0.0.0.0", 5000), Handler)
    print("Server running on http://0.0.0.0:5000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()