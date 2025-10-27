
import sqlite3
from typing import Optional

def temperature_for_location(latitude: float, longitude: float, date: str) -> Optional[float]:
    """\n    Get temperature for a specific location and date.\n    \n    Args:\n        latitude: Latitude coordinate (-90 to 90)\n        longitude: Longitude coordinate (-180 to 180)\n        date: Date string in format YYYY-MM-DD\n        \n    Returns:\n        Temperature as float or None if not found\n    """
    conn = None
    temperature = None
    
    try:
        # Input validation
        if not date or not date.strip():
            raise ValueError("Date cannot be null or empty")
        
        if latitude < -90 or latitude > 90:
            raise ValueError("Invalid latitude")
        
        if longitude < -180 or longitude > 180:
            raise ValueError("Invalid longitude")
        
        # Connect to database
        conn = sqlite3.connect('weather.db')
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        query = "SELECT temperature FROM weather_data WHERE latitude = ? AND longitude = ? AND date = ?"
        cursor.execute(query, (latitude, longitude, date))
        
        result = cursor.fetchone()
        if result:
            temperature = result[0]
            
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except ValueError as e:
        print(f"Validation error: {e}")
    finally:
        if conn:
            conn.close()
    
    return temperature


if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    temp1 = temperature_for_location(40.7128, -74.0060, "2023-01-15")
    print(f"Temperature: {temp1}")
    
    print("\\nTest Case 2:")
    temp2 = temperature_for_location(51.5074, -0.1278, "2023-06-20")
    print(f"Temperature: {temp2}")
    
    print("\\nTest Case 3:")
    temp3 = temperature_for_location(35.6762, 139.6503, "2023-12-25")
    print(f"Temperature: {temp3}")
    
    print("\\nTest Case 4:")
    temp4 = temperature_for_location(-33.8688, 151.2093, "2023-03-10")
    print(f"Temperature: {temp4}")
    
    print("\\nTest Case 5:")
    temp5 = temperature_for_location(48.8566, 2.3522, "2023-09-05")
    print(f"Temperature: {temp5}")
