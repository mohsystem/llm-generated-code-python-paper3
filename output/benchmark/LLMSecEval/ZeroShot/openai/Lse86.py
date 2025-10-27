import os
import json
import re
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

SAFE_FILE_PATTERN = re.compile(r'^[A-Za-z0-9._-]{1,128}$')
TABLE_NAME = "temperature_data"

def _validate_inputs(latitude, longitude, year, month, day, grib_file):
    if latitude is None or not (-90.0 <= latitude <= 90.0):
        raise ValueError("Invalid latitude")
    if longitude is None or not (-180.0 <= longitude <= 180.0):
        raise ValueError("Invalid longitude")
    if not (1900 <= year <= 2100):
        raise ValueError("Invalid year")
    if not (1 <= month <= 12):
        raise ValueError("Invalid month")
    if not (1 <= day <= 31):
        raise ValueError("Invalid day")
    import datetime
    try:
        datetime.date(year, month, day)
    except Exception:
        raise ValueError("Invalid date")
    if grib_file is None or not SAFE_FILE_PATTERN.match(grib_file):
        raise ValueError("Invalid grib_file")

# Function: accepts input as parameters and returns max temperature or None
def query_max_temperature(latitude, longitude, year, month, day, grib_file):
    _validate_inputs(latitude, longitude, year, month, day, grib_file)
    db_url = os.environ.get("DB_URL")
    db_user = os.environ.get("DB_USER")
    db_pass = os.environ.get("DB_PASS")
    if not (db_url and db_user and db_pass):
        raise RuntimeError("Database configuration not set via environment variables.")

    # Expect DB_URL like: mysql+mysqlconnector://host:port/schema or mysql://host:port/schema
    # Parse compatible with mysql-connector-python
    # Prefer mysql.connector
    try:
        import mysql.connector  # type: ignore
    except Exception:
        raise RuntimeError("mysql-connector-python is required.")

    host = "localhost"
    port = 3306
    database = None
    # Simple parse for mysql://host:port/schema
    try:
        if db_url.startswith("mysql://") or db_url.startswith("mysql+mysqlconnector://"):
            stripped = db_url.split("://", 1)[1]
            # stripped = host:port/schema
            if "/" in stripped:
                hp, database = stripped.split("/", 1)
            else:
                hp = stripped
            if ":" in hp:
                host, port_s = hp.split(":", 1)
                port = int(port_s)
            else:
                host = hp
        else:
            # fallback: allow full DSN parts via env DB_HOST, DB_PORT, DB_NAME
            host = os.environ.get("DB_HOST", "localhost")
            port = int(os.environ.get("DB_PORT", "3306"))
            database = os.environ.get("DB_NAME")
    except Exception:
        raise RuntimeError("Invalid DB_URL format.")

    if not database:
        database = os.environ.get("DB_NAME")
    if not database:
        raise RuntimeError("Database name not provided in DB_URL or DB_NAME env var.")

    conn = None
    try:
        conn = mysql.connector.connect(
            host=host, port=port, database=database,
            user=db_user, password=db_pass, autocommit=True,
            connection_timeout=5
        )
        query = f"SELECT MAX(temperature) AS max_temp FROM {TABLE_NAME} WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s AND grib_file = %s"
        args = (float(latitude), float(longitude), int(year), int(month), int(day), grib_file)
        with conn.cursor() as cur:
            cur.execute(query, args)
            row = cur.fetchone()
            if row and row[0] is not None:
                return float(row[0])
            return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

def _json_error(status, message):
    return status, json.dumps({"status": status, "message": message}, separators=(",", ":"))

def _handle_temperature_for_location(query_params):
    try:
        latitude = float(query_params.get("latitude", [None])[0])
        longitude = float(query_params.get("longitude", [None])[0])
        year = int(query_params.get("year", [None])[0])
        month = int(query_params.get("month", [None])[0])
        day = int(query_params.get("day", [None])[0])
        grib_file = query_params.get("grib_file", [None])[0]
        _validate_inputs(latitude, longitude, year, month, day, grib_file)
    except (TypeError, ValueError):
        return _json_error(400, "Invalid or missing parameters.")

    try:
        res = query_max_temperature(latitude, longitude, year, month, day, grib_file)
        if res is None:
            body = {
                "status": 404,
                "message": "No temperature found for given parameters.",
                "latitude": latitude,
                "longitude": longitude,
                "year": year,
                "month": month,
                "day": day,
                "grib_file": grib_file
            }
            return 404, json.dumps(body, separators=(",", ":"))
        else:
            body = {
                "status": 200,
                "latitude": latitude,
                "longitude": longitude,
                "year": year,
                "month": month,
                "day": day,
                "grib_file": grib_file,
                "max_temperature": res,
                "unit": "K"
            }
            return 200, json.dumps(body, separators=(",", ":"))
    except RuntimeError:
        return _json_error(500, "Server configuration error.")
    except Exception:
        return _json_error(500, "Database error.")

class _TempHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/temperature_for_location"):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query, keep_blank_values=False, strict_parsing=False)
            status, body = _handle_temperature_for_location(params)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        else:
            self.send_response(404)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'{"status":404,"message":"Not Found"}')

def start_server(port=8081):
    httpd = HTTPServer(("0.0.0.0", port), _TempHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd

if __name__ == "__main__":
    # Start server (optional)
    if os.environ.get("RUN_SERVER", "1") != "0":
        start_server(8081)
        print("Python server listening on 8081")

    # 5 test cases calling the function directly (requires DB configuration)
    tests = [
        (37.7749, -122.4194, 2023, 7, 15, "gfs_20230715.grb2"),
        (40.7128, -74.0060, 2022, 12, 25, "era5_20221225.grib"),
        (51.5074, -0.1278, 2021, 1, 1, "icon_20210101.grb"),
        (-33.8688, 151.2093, 2020, 2, 29, "gfs_20200229.grb2"),
        (35.6895, 139.6917, 2019, 9, 10, "jra55_20190910.grb")
    ]
    for t in tests:
        try:
            res = query_max_temperature(*t)
            print("Test result:", "null" if res is None else res)
        except Exception as e:
            print("Test error:", str(e))