import sqlite3
import math
from typing import Optional

DB_PATH = "weather_secure_py.db"

def _is_valid_lat_lon(lat: float, lon: float) -> bool:
    if lat is None or lon is None:
        return False
    if math.isnan(lat) or math.isnan(lon):
        return False
    return -90.0 <= float(lat) <= 90.0 and -180.0 <= float(lon) <= 180.0

def _is_valid_date(date: str) -> bool:
    if not isinstance(date, str) or len(date) != 10:
        return False
    for i, c in enumerate(date):
        if i in (4, 7):
            if c != '-':
                return False
        else:
            if not c.isdigit():
                return False
    try:
        year = int(date[0:4])
        month = int(date[5:7])
        day = int(date[8:10])
        if year < 1 or year > 9999:
            return False
        if month < 1 or month > 12:
            return False
        # days in month with leap year handling
        dim = [31, 29 if ((year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        if day < 1 or day > dim[month - 1]:
            return False
        # For Feb 29 non-leap year adjust
        if month == 2 and day == 29 and not (((year % 4 == 0 and year % 100 != 0) or (year % 400 == 0))):
            return False
        return True
    except Exception:
        return False

# Returns temperature as float, or math.nan on error/not found.
# Intended to be called for /api/temperature_for_location
def temperature_for_location(latitude: float, longitude: float, date: str) -> float:
    if not _is_valid_lat_lon(latitude, longitude) or not _is_valid_date(date):
        return math.nan

    try:
        with sqlite3.connect(DB_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            sql = "SELECT temp FROM temperatures WHERE lat = ? AND lon = ? AND date = ? LIMIT 1"
            cur = conn.execute(sql, (float(latitude), float(longitude), date))
            row = cur.fetchone()
            return float(row[0]) if row is not None else math.nan
    except Exception:
        return math.nan

def _seed_database():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS temperatures (lat REAL NOT NULL, lon REAL NOT NULL, date TEXT NOT NULL, temp REAL NOT NULL, PRIMARY KEY(lat, lon, date))")
            conn.execute("DELETE FROM temperatures")
            conn.executemany(
                "INSERT INTO temperatures(lat, lon, date, temp) VALUES(?,?,?,?)",
                [
                    (37.7749, -122.4194, "2025-01-01", 12.3),
                    (40.7128,  -74.0060, "2025-01-01", 5.7),
                    (34.0522, -118.2437, "2025-01-02", 15.2),
                    (51.5074,   -0.1278, "2025-01-01", 7.1),
                    (-33.8688, 151.2093, "2025-01-03", 22.8),
                ],
            )
            conn.commit()
    except Exception:
        pass

if __name__ == "__main__":
    _seed_database()
    # 5 test cases
    tests = [
        (37.7749, -122.4194, "2025-01-01"),
        (40.7128,  -74.0060, "2025-01-01"),
        (34.0522, -118.2437, "2025-01-02"),
        (0.0, 0.0, "2025-01-01"),    # not found
        (100.0, 0.0, "2025-13-40"),  # invalid
    ]
    for i, (la, lo, da) in enumerate(tests, 1):
        t = temperature_for_location(la, lo, da)
        print(f"Test{i}: {'NaN' if math.isnan(t) else t}")