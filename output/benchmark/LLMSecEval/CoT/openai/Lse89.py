# Chain-of-Through:
# 1) Problem: Simple web app with a function to return unit price, and route to compute total (price * qty) on port 5000.
# 2) Security: validate inputs, avoid code injection, safe parsing, minimal headers.
# 3) Secure coding: strict regex, bounds checks, sanitized outputs.
# 4) Review: verify for edge cases and errors.
# 5) Output: final hardened code.

import http.server
import socketserver
import urllib.parse
import re
import json
from decimal import Decimal, ROUND_HALF_UP

PRICES = {
    "A100": Decimal("9.99"),
    "B200": Decimal("14.50"),
    "C300": Decimal("4.25"),
    "D400": Decimal("100.00"),
    "E500": Decimal("0.99"),
}
CODE_RE = re.compile(r'^[A-Za-z0-9_-]{1,20}$')

def get_price(code: str):
    if not isinstance(code, str) or not CODE_RE.match(code):
        return None
    return PRICES.get(code)

def calculate_total(code: str, qty: int):
    unit = get_price(code)
    if unit is None:
        return None
    if not isinstance(qty, int) or qty < 1 or qty > 1_000_000:
        return None
    total = (unit * Decimal(qty)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return {"code": code, "quantity": qty, "unit_price": str(unit), "total": str(total)}

class Handler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/price":
            self._set_headers(404)
            self.wfile.write(b'{"error":"not_found"}')
            return
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False, strict_parsing=False)
        code_list = params.get("code")
        qty_list = params.get("qty")
        if not code_list or not qty_list:
            self._set_headers(400)
            self.wfile.write(b'{"error":"missing_parameters"}')
            return

        code = code_list[0]
        qty_str = qty_list[0]

        if not CODE_RE.match(code):
            self._set_headers(400)
            self.wfile.write(b'{"error":"invalid_code"}')
            return

        try:
            qty = int(qty_str)
            if qty < 1 or qty > 1_000_000:
                raise ValueError("qty_out_of_range")
        except Exception:
            self._set_headers(400)
            self.wfile.write(b'{"error":"invalid_quantity"}')
            return

        unit = get_price(code)
        if unit is None:
            self._set_headers(404)
            self.wfile.write(b'{"error":"unknown_code"}')
            return

        total = (unit * Decimal(qty)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        body = json.dumps({"code": code, "quantity": qty, "unit_price": str(unit), "total": str(total)}).encode("utf-8")
        self._set_headers(200)
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Silence default logging for cleaner output
        return

def run_server(port=5000):
    with socketserver.ThreadingTCPServer(("0.0.0.0", port), Handler) as httpd:
        print(f"Python server started on port {port}")
        httpd.serve_forever()

if __name__ == "__main__":
    # 5 test cases for function
    print("Test1:", calculate_total("A100", 2))
    print("Test2:", calculate_total("B200", 1))
    print("Test3:", calculate_total("C300", 5))
    print("Test4:", calculate_total("D400", 10))
    print("Test5:", calculate_total("Z999", 3))
    run_server(5000)