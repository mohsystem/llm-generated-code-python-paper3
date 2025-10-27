import math
import threading
from datetime import datetime
from typing import Optional

class _SecureDB:
    def __init__(self):
        self._lock = threading.Lock()
        self._data = {}

    def _key(self, lat: float, lon: float, date_str: str) -> str:
        return f"{lat:.6f}|{lon:.6f}|{date_str}"

    def insert(self, latitude: float, longitude: float, date_iso: str, temperature: float) -> None:
        with self._lock:
            self._data[self._key(latitude, longitude, date_iso)] = float(temperature)

    def get_temperature(self, latitude: float, longitude: float, date_iso: str) -> Optional[float]:
        with self._lock:
            return self._data.get(self._key(latitude, longitude, date_iso))

_DB_INSTANCE = _SecureDB()

def _is_valid_lat(lat: float) -> bool:
    return isinstance(lat, (int, float)) and math.isfinite(lat) and -90.0 <= lat <= 90.0

def _is_valid_lon(lon: float) -> bool:
    return isinstance(lon, (int, float)) and math.isfinite(lon) and -180.0 <= lon <= 180.0

def _is_valid_iso_date(date_str: str) -> bool:
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except Exception:
        return False

# Function: accepts inputs as parameters and returns the temperature; returns math.nan if not found or invalid input
def temperature_for_location(latitude: float, longitude: float, date_iso: str) -> float:
    if not _is_valid_lat(latitude) or not _is_valid_lon(longitude):
        return math.nan
    if not _is_valid_iso_date(date_iso):
        return math.nan
    result = _DB_INSTANCE.get_temperature(latitude, longitude, date_iso)
    return float(result) if result is not None else math.nan

def _seed_sample_data():
    _DB_INSTANCE.insert(37.7749, -122.4194, "2023-10-01", 20.5)
    _DB_INSTANCE.insert(40.7128, -74.0060, "2023-10-01", 18.1)
    _DB_INSTANCE.insert(51.5074, -0.1278, "2023-12-25", 5.2)
    _DB_INSTANCE.insert(-33.8688, 151.2093, "2024-01-15", 27.3)
    _DB_INSTANCE.insert(35.6895, 139.6917, "2023-07-20", 30.4)

if __name__ == "__main__":
    _seed_sample_data()
    # 5 test cases
    print("Test1:", temperature_for_location(37.7749, -122.4194, "2023-10-01"))  # 20.5
    print("Test2:", temperature_for_location(35.6895, 139.6917, "2023-07-20"))   # 30.4
    print("Test3:", temperature_for_location(37.7749, -122.4194, "2023-10-02"))  # nan
    print("Test4:", temperature_for_location(100.0, -122.4194, "2023-10-01"))    # nan
    print("Test5:", temperature_for_location(40.7128, -74.0060, "2023-13-01"))   # nan