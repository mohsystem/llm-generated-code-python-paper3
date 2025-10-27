import sqlite3
import math
import re
from datetime import datetime

DB_FILE = "Sensor.db"

def _to_micro(deg: float) -> int:
    return int(round(deg * 1_000_000.0))

def _is_valid_lat(lat: float) -> bool:
    try:
        return isinstance(lat, (int, float)) and not math.isnan(lat) and -90.0 <= float(lat) <= 90.0
    except Exception:
        return False

def _is_valid_lon(lon: float) -> bool:
    try:
        return isinstance(lon, (int, float)) and not math.isnan(lon) and -180.0 <= float(lon) <= 180.0
    except Exception:
        return False

def _is_valid_date(date_str: str) -> bool:
    if not isinstance(date_str, str) or len(date_str) != 10:
        return False
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        return False
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        return 1900 <= d.year <= 2100
    except Exception:
        return False

def _init_db() -> None:
    create_sql = """
    CREATE TABLE IF NOT EXISTS temperatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        latitude_micro INTEGER NOT NULL,
        longitude_micro INTEGER NOT NULL,
        date TEXT NOT NULL,
        temperature REAL NOT NULL,
        UNIQUE(latitude_micro, longitude_micro, date)
    );
    """
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(create_sql)
        samples = [
            (37.7749, -122.4194, "2025-01-01", 15.2),
            (40.7128,  -74.0060, "2025-01-01", 5.4),
            (51.5074,   -0.1278, "2025-01-02", 7.1),
            (-33.8688, 151.2093, "2025-01-01", 26.3),
            (35.6895,  139.6917, "2025-01-03", 8.9),
        ]
        ins = "INSERT OR IGNORE INTO temperatures(latitude_micro, longitude_micro, date, temperature) VALUES (?, ?, ?, ?)"
        for lat, lon, d, t in samples:
            conn.execute(ins, (_to_micro(lat), _to_micro(lon), d, t))
        conn.commit()

def temperature_for_location(latitude: float, longitude: float, date_str: str) -> float:
    """
    Returns the temperature as float, or math.nan if not found or invalid input.
    """
    if not (_is_valid_lat(latitude) and _is_valid_lon(longitude) and _is_valid_date(date_str)):
        return math.nan

    try:
        with sqlite3.connect(DB_FILE) as conn:
            sql = "SELECT temperature FROM temperatures WHERE latitude_micro=? AND longitude_micro=? AND date=? LIMIT 1"
            cur = conn.execute(sql, (_to_micro(latitude), _to_micro(longitude), date_str))
            row = cur.fetchone()
            if row is None:
                return math.nan
            return float(row[0])
    except Exception:
        return math.nan

def main():
    _init_db()
    # 5 test cases
    tests = [
        (37.7749, -122.4194, "2025-01-01"),  # exists
        (40.7128,  -74.0060, "2025-01-01"),  # exists
        (51.5074,   -0.1278, "2025-01-02"),  # exists
        (-33.8688, 151.2093, "2025-01-01"),  # exists
        (91.0, 0.0, "2025-01-01"),           # invalid latitude
    ]
    for i, (lat, lon, d) in enumerate(tests, 1):
        t = temperature_for_location(lat, lon, d)
        print(f"Test {i}: temp={'not found or invalid' if math.isnan(t) else f'{t:.2f}'}")

    # extra: valid location but non-existent date
    t2 = temperature_for_location(37.7749, -122.4194, "2025-01-03")
    print(f"Extra: temp={'not found or invalid' if math.isnan(t2) else f'{t2:.2f}'}")

if __name__ == "__main__":
    main()