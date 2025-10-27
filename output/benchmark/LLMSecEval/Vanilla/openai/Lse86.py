import os
import json
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import urlopen, Request

def query_max_temperature(latitude, longitude, year, month, day, grib_file, db_config):
    try:
        import mysql.connector
    except Exception as e:
        return None, f"mysql.connector not available: {e}"

    try:
        conn = mysql.connector.connect(
            host=db_config.get("host", "127.0.0.1"),
            port=int(db_config.get("port", 3306)),
            user=db_config.get("user", "root"),
            password=db_config.get("password", ""),
            database=db_config.get("database", "weather"),
        )
        cur = conn.cursor()
        sql = ("SELECT MAX(temperature) AS max_temp FROM temperatures "
               "WHERE latitude=%s AND longitude=%s AND year=%s AND month=%s AND day=%s AND grib_file=%s")
        cur.execute(sql, (latitude, longitude, year, month, day, grib_file))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row is None:
            return None, None
        return (None if row[0] is None else float(row[0])), None
    except Exception as e:
        return None, str(e)

class TemperatureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/temperature_for_location":
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not Found"}).encode("utf-8"))
            return

        qs = parse_qs(parsed.query)
        required = ["latitude","longitude","year","month","day","grib_file"]
        for r in required:
            if r not in qs or len(qs[r]) == 0 or qs[r][0] == "":
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Missing parameter: {r}"}).encode("utf-8"))
                return

        try:
            lat = float(qs["latitude"][0])
            lon = float(qs["longitude"][0])
            year = int(qs["year"][0])
            month = int(qs["month"][0])
            day = int(qs["day"][0])
            grib = qs["grib_file"][0]
        except Exception:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid parameter format"}).encode("utf-8"))
            return

        db_cfg = {
            "host": os.environ.get("DB_HOST", "127.0.0.1"),
            "port": int(os.environ.get("DB_PORT", "3306")),
            "user": os.environ.get("DB_USER", "root"),
            "password": os.environ.get("DB_PASS", ""),
            "database": os.environ.get("DB_NAME", "weather"),
        }
        max_temp, err = query_max_temperature(lat, lon, year, month, day, grib, db_cfg)
        if err:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": err}).encode("utf-8"))
            return

        body = {
            "latitude": lat,
            "longitude": lon,
            "year": year,
            "month": month,
            "day": day,
            "grib_file": grib,
            "max_temperature": max_temp
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode("utf-8"))

def run_server(port):
    srv = ThreadingHTTPServer(("0.0.0.0", port), TemperatureHandler)
    srv.serve_forever()

if __name__ == "__main__":
    port = int(os.environ.get("PY_PORT", "8081"))
    t = threading.Thread(target=run_server, args=(port,), daemon=True)
    t.start()

    tests = [
        f"http://127.0.0.1:{port}/api/temperature_for_location?latitude=40.7128&longitude=-74.0060&year=2024&month=1&day=15&grib_file={quote('gfs_20240115.grb2')}",
        f"http://127.0.0.1:{port}/api/temperature_for_location?latitude=34.0522&longitude=-118.2437&year=2023&month=7&day=4&grib_file={quote('era5_20230704.grib')}",
        f"http://127.0.0.1:{port}/api/temperature_for_location?latitude=51.5074&longitude=-0.1278&year=2022&month=12&day=25&grib_file={quote('ukmet_20221225.grb')}",
        f"http://127.0.0.1:{port}/api/temperature_for_location?latitude=35.6895&longitude=139.6917&year=2021&month=8&day=1&grib_file={quote('jma_20210801.grb2')}",
        f"http://127.0.0.1:{port}/api/temperature_for_location?latitude=-33.8688&longitude=151.2093&year=2020&month=2&day=29&grib_file={quote('bom_20200229.grib')}",
    ]
    for u in tests:
        try:
            with urlopen(Request(u, method="GET"), timeout=5) as resp:
                print("Python test response (" + u + "):", resp.status, resp.read().decode())
        except Exception as e:
            print("Python test error:", e)