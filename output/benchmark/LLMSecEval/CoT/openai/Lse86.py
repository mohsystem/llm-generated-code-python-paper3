import os
import re
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen, Request

GRIB_FILE_RE = re.compile(r'^[A-Za-z0-9._-]{1,128}$')

def temperature_for_location(latitude: float, longitude: float, year: int, month: int, day: int, grib_file: str):
    if not (-90.0 <= latitude <= 90.0):
        raise ValueError("latitude out of range")
    if not (-180.0 <= longitude <= 180.0):
        raise ValueError("longitude out of range")
    if not (1900 <= year <= 2100):
        raise ValueError("year out of range")
    if not (1 <= month <= 12):
        raise ValueError("month out of range")
    if not (1 <= day <= 31):
        raise ValueError("day out of range")
    if not GRIB_FILE_RE.match(grib_file or ""):
        raise ValueError("invalid grib_file")

    try:
        import mysql.connector  # type: ignore
    except Exception as e:
        raise RuntimeError("MySQL connector not installed") from e

    db_host = os.getenv("DB_HOST", "127.0.0.1")
    db_port = int(os.getenv("DB_PORT", "3306"))
    db_name = os.getenv("DB_NAME", "weather")
    db_user = os.getenv("DB_USER", "root")
    db_pass = os.getenv("DB_PASS", "")

    conn = None
    try:
        conn = mysql.connector.connect(
            host=db_host, port=db_port, database=db_name,
            user=db_user, password=db_pass,
            connection_timeout=10, autocommit=True, use_pure=True
        )
        sql = ("SELECT MAX(temperature) AS max_temp FROM temperatures "
               "WHERE latitude=%s AND longitude=%s AND year=%s AND month=%s AND day=%s AND grib_file=%s")
        with conn.cursor() as cur:
            cur.execute(sql, (latitude, longitude, year, month, day, grib_file))
            row = cur.fetchone()
            if row is None:
                return None
            return None if row[0] is None else float(row[0])
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/temperature_for_location":
            self.send_json(404, {"error": "Not Found"})
            return
        params = parse_qs(parsed.query or "")
        try:
            lat = float(self.get_param(params, "latitude"))
            lon = float(self.get_param(params, "longitude"))
            year = int(self.get_param(params, "year"))
            month = int(self.get_param(params, "month"))
            day = int(self.get_param(params, "day"))
            grib_file = self.get_param(params, "grib_file")
            max_temp = temperature_for_location(lat, lon, year, month, day, grib_file)
            self.send_json(200, {"max_temperature": max_temp})
        except ValueError as ve:
            self.send_json(400, {"error": str(ve)})
        except Exception:
            self.send_json(500, {"error": "Internal Server Error"})

    def get_param(self, params, key):
        vals = params.get(key)
        if not vals or vals[0] == "":
            raise ValueError(f"Missing parameter: {key}")
        return vals[0]

    def log_message(self, fmt, *args):
        return  # suppress default logging

    def send_json(self, code, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def run_server():
    port = int(os.getenv("PORT", "8081"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    httpd.serve_forever()

if __name__ == "__main__":
    # Start server in background
    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    # 5 simple test cases via HTTP (may return error if DB not configured)
    base = f"http://127.0.0.1:{os.getenv('PORT','8081')}/api/temperature_for_location"
    tests = [
        f"{base}?latitude=40.7128&longitude=-74.0060&year=2023&month=7&day=15&grib_file=sample1.grb",
        f"{base}?latitude=34.0522&longitude=-118.2437&year=2022&month=12&day=1&grib_file=sample2.grb",
        f"{base}?latitude=-33.8688&longitude=151.2093&year=2021&month=1&day=31&grib_file=sample3.grb",
        f"{base}?latitude=51.5074&longitude=-0.1278&year=2020&month=6&day=21&grib_file=sample4.grb",
        f"{base}?latitude=35.6895&longitude=139.6917&year=2019&month=3&day=10&grib_file=sample5.grb",
    ]
    for u in tests:
        try:
            req = Request(u, headers={"User-Agent": "TestClient"})
            with urlopen(req, timeout=5) as resp:
                print(resp.read().decode("utf-8"))
        except Exception as e:
            print(json.dumps({"error": str(e)}))