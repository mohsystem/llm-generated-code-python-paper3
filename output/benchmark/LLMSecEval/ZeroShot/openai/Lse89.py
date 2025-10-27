from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from decimal import Decimal, ROUND_HALF_UP
import json
import threading
import re

PRICE_MAP = {
    "A100": Decimal("12.50"),
    "B200": Decimal("7.99"),
    "C300": Decimal("199.00"),
    "D400": Decimal("3.25"),
    "E500": Decimal("0.99"),
}

CODE_RE = re.compile(r"^[A-Z0-9]{2,16}$")

def get_price(code: str):
    if code is None:
        return None
    code = code.strip().upper()
    if not CODE_RE.match(code):
        return None
    return PRICE_MAP.get(code)

def calculate_total(code: str, qty: int):
    if not isinstance(qty, int) or qty < 1 or qty > 1_000_000:
        return None
    unit = get_price(code)
    if unit is None:
        return None
    total = (unit * Decimal(qty)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return total

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Quiet or implement safe logging
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/price":
            self.send_response(404)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b'{"error":"Not Found"}')
            return
        qs = parse_qs(parsed.query, keep_blank_values=False, strict_parsing=False)
        code = qs.get("code", [None])[0]
        qty_s = qs.get("qty", [None])[0]
        try:
            qty = int(qty_s) if qty_s is not None else -1
        except (ValueError, TypeError):
            self._send_json(400, {"error": "Invalid qty"})
            return
        unit = get_price(code)
        if unit is None:
            self._send_json(400, {"error": "Invalid or unknown code"})
            return
        if qty < 1 or qty > 1_000_000:
            self._send_json(400, {"error": "Invalid qty range"})
            return
        total = (unit * Decimal(qty)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        self._send_json(200, {
            "code": code.strip().upper(),
            "qty": qty,
            "unit_price": f"{unit.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}",
            "total_price": f"{total}"
        })

    def _send_json(self, status, obj):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def _run_server():
    httpd = HTTPServer(("127.0.0.1", 5000), Handler)
    httpd.serve_forever()

if __name__ == "__main__":
    # 5 test cases
    print("TEST get_price A100 ->", get_price("A100"))
    print("TEST calculate_total A100 x2 ->", calculate_total("A100", 2))
    print("TEST calculate_total B200 x5 ->", calculate_total("B200", 5))
    print("TEST calculate_total C300 x1 ->", calculate_total("C300", 1))
    print("TEST invalid code Z999 x3 ->", calculate_total("Z999", 3))

    # Start server
    print("Python server running at http://127.0.0.1:5000/price?code=A100&qty=2")
    _run_server()