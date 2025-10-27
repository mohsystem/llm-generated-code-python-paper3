import sqlite3
import re
from typing import Optional

DB_PATH = "Sensor.db"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

def _init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS temperatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lat REAL NOT NULL,
                lon REAL NOT NULL,
                date TEXT NOT NULL,
                temp REAL NOT NULL,
                UNIQUE(lat, lon, date)
            );
        """)
        conn.commit()

def _seed_data() -> None:
    rows = [
        (37.7749, -122.4194, "2023-07-01", 20.5),
        (40.7128, -74.0060, "2023-07-01", 27.3),
        (51.5074, -0.1278, "2023-12-25", 5.2),
        (35.6895, 139.6917, "2023-04-15", 18.0),
        (48.8566, 2.3522, "2023-07-14", 25.0),
    ]
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO temperatures (lat, lon, date, temp) VALUES (?, ?, ?, ?);",
            rows
        )
        conn.commit()

def _valid_lat_lon(lat: float, lon: float) -> bool:
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0

def _valid_date(date: str) -> bool:
    return isinstance(date, str) and bool(DATE_RE.match(date))

# Function to be called when /api/temperature_for_location is requested
def temperature_for_location(lat: float, lon: float, date: str) -> Optional[float]:
    if not _valid_lat_lon(lat, lon) or not _valid_date(date):
        return None
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute(
                "SELECT temp FROM temperatures WHERE lat = ? AND lon = ? AND date = ?;",
                (lat, lon, date)
            )
            row = cur.fetchone()
            return float(row[0]) if row else None
    except sqlite3.Error:
        return None

if __name__ == "__main__":
    _init_db()
    _seed_data()

    tests = [
        (37.7749, -122.4194, "2023-07-01"),
        (40.7128, -74.0060, "2023-07-01"),
        (51.5074, -0.1278, "2023-01-01"),  # not found
        (95.0, 10.0, "2023-07-01"),        # invalid lat
        (48.8566, 2.3522, "2023-07-14"),
    ]
    for i, (lat, lon, date) in enumerate(tests, 1):
        res = temperature_for_location(lat, lon, date)
        print(f"Test{i}: {res if res is not None else 'not found or invalid'}")