import sqlite3
import math
from datetime import datetime

DB_PATH = "weather.db"

def temperature_for_location(latitude: float, longitude: float, date_str: str):
    if not _is_valid_lat(latitude) or not _is_valid_lon(longitude) or not _is_valid_date(date_str):
        return None
    try:
        with sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.cursor()
            cur.execute(
                "SELECT temperature FROM temperatures WHERE latitude = ? AND longitude = ? AND date = ? LIMIT 1",
                (float(latitude), float(longitude), date_str),
            )
            row = cur.fetchone()
            return float(row[0]) if row is not None else None
    except sqlite3.Error:
        return None

def _is_valid_lat(lat: float) -> bool:
    try:
        return math.isfinite(lat) and -90.0 <= float(lat) <= 90.0
    except Exception:
        return False

def _is_valid_lon(lon: float) -> bool:
    try:
        return math.isfinite(lon) and -180.0 <= float(lon) <= 180.0
    except Exception:
        return False

def _is_valid_date(date_str: str) -> bool:
    if not isinstance(date_str, str) or len(date_str) != 10:
        return False
    if date_str[4] != '-' or date_str[7] != '-':
        return False
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except ValueError:
        return False

def _setup_db():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS temperatures (
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    date TEXT NOT NULL,
                    temperature REAL NOT NULL,
                    PRIMARY KEY (latitude, longitude, date)
                )
            """)
            cur.execute("DELETE FROM temperatures")
            cur.executemany(
                "INSERT OR REPLACE INTO temperatures (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)",
                [
                    (10.0, 20.0, "2025-01-01", 23.5),
                    (10.0, 20.0, "2025-01-02", 24.0),
                    (40.7128, -74.0060, "2023-12-25", -1.0),
                    (-33.8688, 151.2093, "2024-07-04", 12.3),
                    (51.5074, -0.1278, "2022-11-11", 8.5),
                ],
            )
            conn.commit()
    except sqlite3.Error:
        pass

if __name__ == "__main__":
    _setup_db()
    tests = [
        (10.0, 20.0, "2025-01-01"),
        (40.7128, -74.0060, "2023-12-25"),
        (10.0, 20.0, "2025-01-03"),  # not found
        (100.0, 20.0, "2025-01-01"), # invalid lat
        (10.0, 20.0, "2025/01/01"),  # invalid date
    ]
    for idx, (la, lo, da) in enumerate(tests, 1):
        print(f"Test {idx}: {temperature_for_location(la, lo, da)}")