
import sqlite3
from datetime import datetime
from typing import Optional, Tuple

class Lse87:
    DB_PATH = "weather.db"
    
    @staticmethod
    def temperature_for_location(latitude_str: str, longitude_str: str, date_str: str) -> Tuple[bool, Optional[float], Optional[str]]:
        """\n        Retrieve temperature for a given location and date.\n        Returns: (success, temperature, error_message)\n        """
        # Input validation
        if not all([latitude_str, longitude_str, date_str]):
            return (False, None, "Missing parameters")
        
        try:
            latitude = float(latitude_str)
            longitude = float(longitude_str)
            
            # Validate ranges
            if not (-90 <= latitude <= 90):
                return (False, None, "Invalid latitude range")
            if not (-180 <= longitude <= 180):
                return (False, None, "Invalid longitude range")
            
            # Validate date format
            datetime.strptime(date_str, '%Y-%m-%d')
            
        except ValueError as e:
            return (False, None, "Invalid input format")
        
        # Database query with parameterized statement
        query = "SELECT temperature FROM weather_data WHERE latitude = ? AND longitude = ? AND date = ?"
        
        try:
            conn = sqlite3.connect(Lse87.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute(query, (latitude, longitude, date_str))
            result = cursor.fetchone()
            
            conn.close()
            
            if result:
                return (True, result[0], None)
            else:
                return (False, None, "No data found")
                
        except sqlite3.Error as e:
            return (False, None, "Database error")
        finally:
            if 'conn' in locals():
                conn.close()


def main():
    """Test cases"""
    print("Test 1: Valid input")
    result1 = Lse87.temperature_for_location("40.7128", "-74.0060", "2024-01-15")
    print(f"Success: {result1[0]}, Temp: {result1[1]}, Error: {result1[2]}")
    
    print("\\nTest 2: Invalid latitude")
    result2 = Lse87.temperature_for_location("100.0", "-74.0060", "2024-01-15")
    print(f"Success: {result2[0]}, Error: {result2[2]}")
    
    print("\\nTest 3: Invalid date format")
    result3 = Lse87.temperature_for_location("40.7128", "-74.0060", "15-01-2024")
    print(f"Success: {result3[0]}, Error: {result3[2]}")
    
    print("\\nTest 4: None parameters")
    result4 = Lse87.temperature_for_location(None, "-74.0060", "2024-01-15")
    print(f"Success: {result4[0]}, Error: {result4[2]}")
    
    print("\\nTest 5: Invalid number format")
    result5 = Lse87.temperature_for_location("abc", "-74.0060", "2024-01-15")
    print(f"Success: {result5[0]}, Error: {result5[2]}")


if __name__ == "__main__":
    main()
