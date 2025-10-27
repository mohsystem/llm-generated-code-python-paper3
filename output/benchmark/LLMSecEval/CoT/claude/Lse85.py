
import sqlite3
from datetime import datetime
from typing import Optional

class Lse85:
    DB_PATH = "Sensor.db"
    
    @staticmethod
    def temperature_for_location(latitude: float, longitude: float, date: str) -> Optional[float]:
        # Input validation
        if not Lse85._is_valid_latitude(latitude):
            return None
        if not Lse85._is_valid_longitude(longitude):
            return None
        if not Lse85._is_valid_date(date):
            return None
        
        query = "SELECT temperature FROM sensor_data WHERE latitude = ? AND longitude = ? AND date = ?"
        
        try:
            with sqlite3.connect(Lse85.DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(query, (latitude, longitude, date))
                result = cursor.fetchone()
                
                if result:
                    return float(result[0])
                return None
                
        except sqlite3.Error as e:
            print(f"Database error occurred")
            return None
    
    @staticmethod
    def _is_valid_latitude(lat: float) -> bool:
        return -90.0 <= lat <= 90.0
    
    @staticmethod
    def _is_valid_longitude(lon: float) -> bool:
        return -180.0 <= lon <= 180.0
    
    @staticmethod
    def _is_valid_date(date: str) -> bool:
        try:
            datetime.strptime(date, "%Y-%m-%d")
            return True
        except ValueError:
            return False

if __name__ == "__main__":
    # Test cases
    print("Test 1:", Lse85.temperature_for_location(40.7128, -74.0060, "2024-01-15"))
    print("Test 2:", Lse85.temperature_for_location(51.5074, -0.1278, "2024-02-20"))
    print("Test 3:", Lse85.temperature_for_location(35.6762, 139.6503, "2024-03-10"))
    print("Test 4 (Invalid lat):", Lse85.temperature_for_location(100.0, -74.0060, "2024-01-15"))
    print("Test 5 (Invalid date):", Lse85.temperature_for_location(40.7128, -74.0060, "2024-13-45"))
