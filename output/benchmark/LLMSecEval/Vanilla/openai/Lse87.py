import sqlite3

def temperature_for_location(latitude, longitude, date_str):
    conn = sqlite3.connect(":memory:")
    try:
        cur = conn.cursor()
        cur.execute("CREATE TABLE temperatures (lat REAL, lon REAL, date TEXT, temp REAL)")
        rows = [
            (37.7749, -122.4194, "2025-01-01", 15.2),
            (40.7128, -74.0060, "2025-01-01", 3.4),
            (34.0522, -118.2437, "2025-01-01", 20.1),
            (51.5074, -0.1278, "2025-01-01", 7.8),
            (35.6895, 139.6917, "2025-01-01", 8.9),
            (37.7749, -122.4194, "2025-02-01", 16.0),
        ]
        cur.executemany("INSERT INTO temperatures(lat, lon, date, temp) VALUES (?,?,?,?)", rows)
        cur.execute("SELECT temp FROM temperatures WHERE lat=? AND lon=? AND date=? LIMIT 1", (latitude, longitude, date_str))
        row = cur.fetchone()
        return row[0] if row is not None else None
    finally:
        conn.close()

if __name__ == "__main__":
    print(temperature_for_location(37.7749, -122.4194, "2025-01-01"))
    print(temperature_for_location(40.7128, -74.0060, "2025-01-01"))
    print(temperature_for_location(34.0522, -118.2437, "2025-01-01"))
    print(temperature_for_location(51.5074, -0.1278, "2025-01-01"))
    print(temperature_for_location(37.7749, -122.4194, "2025-02-01"))