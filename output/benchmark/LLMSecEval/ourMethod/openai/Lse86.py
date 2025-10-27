#!/usr/bin/env python3
import json
import os
import re
import socket
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, quote
from urllib.request import urlopen, Request

PORT = 8082
ENDPOINT = "/api/temperature_for_location"
GRIB_FILE_ALLOWED = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

try:
    import mysql.connector  # type: ignore
    _MYSQL_AVAILABLE = True
except Exception:
    _MYSQL_AVAILABLE = False

def parse_float_in_range(s: str, mn: float, mx: float):
    if s is None or len(s) > 64:
        return None
    try:
        v = float(s)
        if v >= mn and v <= mx:
            return v
    except Exception:
        return None
    return None

def parse_int_in_range(s: str, mn: int, mx: int):
    if s is None or len(s) > 16:
        return None
    try:
        v = int(s)
        if v >= mn and v <= mx:
            return v
    except Exception:
        return None
    return None

def query_max_temperature(latitude: float, longitude: float, year: int, month: int, day: int, grib_file: str):
    host = os.getenv("DB_HOST")
    port = os.getenv("DB_PORT")
    db = os.getenv("DB_NAME")
    user = os.getenv("DB_USER")
    pw = os.getenv("DB_PASSWORD")

    if not (host and port and db and user and pw):
        return {"success": False, "error": "database_not_configured"}

    if not _MYSQL_AVAILABLE:
        return {"success": False, "error": "database_not_configured"}

    try:
        conn = mysql.connector.connect(
            host=host,
            port=int(port),
            database=db,
            user=user,
            password=pw,
            connection_timeout=5,
            use_pure=True,
            ssl_disabled=True
        )
        try:
            sql = ("SELECT MAX(temp_c) AS max_temp FROM temperatures "
                   "WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s AND grib_file = %s")
            with conn.cursor() as cur:
                cur.execute(sql, (latitude, longitude, year, month, day, grib_file))
                row = cur.fetchone()
                if not row or row[0] is None:
                    return {"success": False, "error": "not_found"}
                return {"success": True, "max_temperature": float(row[0])}
        finally:
            conn.close()
    except Exception:
        return {"success": False, "error": "internal_error"}

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        try:
            if not self.path.startswith(ENDPOINT):
                self._send_json(404, {"error": "not_found"})
                return
            parsed = urlparse(self.path)
            if parsed.path != ENDPOINT:
                self._send_json(404, {"error": "not_found"})
                return

            if parsed.query is None or len(parsed.query) > 2048:
                self._send_json(400, {"error": "invalid_param"})
                return

            params = {}
            for k, v in parse_qs(parsed.query, keep_blank_values=False, strict_parsing=False).items():
                if not v:
                    continue
                key = unquote(k)[:64]
                val = unquote(v[0])[:256]
                params[key] = val

            required = ["latitude", "longitude", "year", "month", "day", "grib_file"]
            for r in required:
                if r not in params:
                    self._send_json(400, {"error": "missing_param"})
                    return

            lat = parse_float_in_range(params["latitude"], -90.0, 90.0)
            lon = parse_float_in_range(params["longitude"], -180.0, 180.0)
            year = parse_int_in_range(params["year"], 1900, 2100)
            month = parse_int_in_range(params["month"], 1, 12)
            day = parse_int_in_range(params["day"], 1, 31)
            grib_file = params["grib_file"]

            if lat is None or lon is None or year is None or month is None or day is None:
                self._send_json(400, {"error": "invalid_param"})
                return
            if grib_file is None or len(grib_file) > 64 or not GRIB_FILE_ALLOWED.match(grib_file):
                self._send_json(400, {"error": "invalid_param"})
                return

            result = query_max_temperature(lat, lon, year, month, day, grib_file)
            if not result.get("success"):
                err = result.get("error", "internal_error")
                if err == "database_not_configured":
                    self._send_json(500, {"error": "database_not_configured"})
                elif err == "not_found":
                    self._send_json(404, {"max_temperature": None})
                else:
                    self._send_json(500, {"error": "internal_error"})
                return

            self._send_json(200, {"max_temperature": result["max_temperature"]})
        except Exception:
            self._send_json(500, {"error": "internal_error"})

    def log_message(self, fmt, *args):
        # Reduce noise; avoid leaking details
        return

    def _send_json(self, status: int, obj):
        body = json.dumps(obj, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run_server():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.serve_forever()

def send_request(query: str) -> str:
    url = f"http://127.0.0.1:{PORT}{ENDPOINT}?{query}"
    req = Request(url, method="GET")
    with urlopen(req, timeout=5) as resp:
        return resp.read().decode("utf-8", "strict")

if __name__ == "__main__":
    th = threading.Thread(target=run_server, daemon=True)
    th.start()

    # Allow server to start
    threading.Event().wait(0.3)

    tests = [
        "latitude=40.7128&longitude=-74.0060&year=2023&month=5&day=23&grib_file=nyc_20230523.grb2",
        "latitude=123.45&longitude=-74.0060&year=2023&month=5&day=23&grib_file=nyc_20230523.grb2",
        "latitude=40.7128&longitude=-74.0060&year=2023&month=5&day=23&grib_file=../../etc/passwd",
        "latitude=40.7128&longitude=-74.0060&year=2023&month=5&grib_file=nyc_20230523.grb2",
        "latitude=-90&longitude=180&year=1900&month=12&day=31&grib_file=edge_case.grb"
    ]
    for q in tests:
        try:
            print("Request:", q)
            print("Response:", send_request(q))
        except Exception as e:
            print("Response:", json.dumps({"error": "internal_error"}))
        print("---")