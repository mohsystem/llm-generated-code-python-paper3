import sqlite3
import re
from datetime import datetime
from typing import Optional, Tuple

DEFAULT_DB_PATH = "Sensor.db"

def _validate_inputs(latitude: float, longitude: float, date_str: str) -> None:
    if latitude is None or not (-90.0 <= latitude <= 90.0):
        raise ValueError("Invalid latitude")
    if longitude is None or not (-180.0 <= longitude <= 180.0):
        raise ValueError("Invalid longitude")
    if not isinstance(date_str, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_str or ""):
        raise ValueError("Invalid date format, expected YYYY-MM-DD")
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Invalid date value")

def init_database(db_path: str = DEFAULT_DB_PATH) -> None:
    if not db_path:
        db_path = DEFAULT_DB_PATH
    with sqlite3.connect(db_path, isolation_level=None) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 3000;")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS SensorReadings(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   latitude REAL NOT NULL,
                   longitude REAL NOT NULL,
                   date TEXT NOT NULL,
                   temperature REAL NOT NULL,
                   UNIQUE(latitude, longitude, date)
               );"""
        )
        data = [
            (37.7749, -122.4194, "2023-08-15", 21.5),
            (37.7749, -122.4194, "2023-08-16", 20.0),
            (40.7128, -74.0060, "2023-08-15", 25.2),
            (34.0522, -118.2437, "2023-08-15", 27.1),
        ]
        conn.executemany(
            "INSERT OR IGNORE INTO SensorReadings(latitude, longitude, date, temperature) VALUES (?,?,?,?);",
            data,
        )

# Function called for /api/temperature_for_location
def temperature_for_location(latitude: float, longitude: float, date_str: str, db_path: str = DEFAULT_DB_PATH) -> Optional[float]:
    _validate_inputs(latitude, longitude, date_str)
    if not db_path:
        db_path = DEFAULT_DB_PATH

    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 3000;")
            cur = conn.execute(
                "SELECT temperature FROM SensorReadings WHERE latitude = ? AND longitude = ? AND date = ?;",
                (latitude, longitude, date_str),
            )
            row = cur.fetchone()
            return float(row[0]) if row is not None else None
    except sqlite3.Error:
        # Minimal error reporting for security; in production use logging
        return None

def _run_tests() -> None:
    init_database(DEFAULT_DB_PATH)
    tests: Tuple[Tuple[float, float, str], ...] = (
        (37.7749, -122.4194, "2023-08-15"),
        (37.7749, -122.4194, "2023-08-16"),
        (40.7128, -74.0060, "2023-08-15"),
        (34.0522, -118.2437, "2023-08-15"),
        (0.0, 0.0, "2023-01-01"),
    )
    for i, (lat, lon, d) in enumerate(tests, 1):
        temp = temperature_for_location(lat, lon, d, DEFAULT_DB_PATH)
        print(f"Test{i}: {temp if temp is not None else 'not found'}")

if __name__ == "__main__":
    _run_tests()