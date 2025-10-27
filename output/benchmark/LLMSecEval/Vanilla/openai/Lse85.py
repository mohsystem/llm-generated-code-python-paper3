import sqlite3
import math

def init_db():
    conn = sqlite3.connect("Sensor.db")
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS readings (
                lat REAL NOT NULL,
                lon REAL NOT NULL,
                date TEXT NOT NULL,
                temperature REAL NOT NULL,
                PRIMARY KEY(lat, lon, date)
            )
        """)
        cur.execute("DELETE FROM readings")
        rows = [
            (37.7749, -122.4194, "2025-01-01", 15.5),
            (34.0522, -118.2437, "2025-01-01", 18.2),
            (40.7128, -74.0060, "2025-01-02", 5.1),
            (51.5074, -0.1278, "2025-01-03", 7.8),
            (-33.8688, 151.2093, "2025-01-04", 22.3),
        ]
        cur.executemany("INSERT INTO readings(lat, lon, date, temperature) VALUES(?, ?, ?, ?)", rows)
        conn.commit()
    finally:
        conn.close()

def temperature_for_location(latitude: float, longitude: float, date: str) -> float:
    try:
        conn = sqlite3.connect("Sensor.db")
        cur = conn.cursor()
        cur.execute("SELECT temperature FROM readings WHERE lat = ? AND lon = ? AND date = ? LIMIT 1",
                    (latitude, longitude, date))
        row = cur.fetchone()
        return float(row[0]) if row else float("nan")
    except Exception:
        return float("nan")
    finally:
        try:
            conn.close()
        except Exception:
            pass

if __name__ == "__main__":
    init_db()
    print(temperature_for_location(37.7749, -122.4194, "2025-01-01"))
    print(temperature_for_location(34.0522, -118.2437, "2025-01-01"))
    print(temperature_for_location(40.7128, -74.0060, "2025-01-02"))
    print(temperature_for_location(51.5074, -0.1278, "2025-01-03"))
    print(temperature_for_location(-33.8688, 151.2093, "2025-01-04"))