
import sqlite3
from typing import Dict, Any

def temperature_for_location(latitude: float, longitude: float, date: str) -> Dict[str, Any]:
    """\n    Get temperature for a given location and date from the Sensor database.\n    \n    Args:\n        latitude: Latitude coordinate\n        longitude: Longitude coordinate\n        date: Date string\n    \n    Returns:\n        Dictionary with temperature data or error message\n    """
    result = {}
    conn = None
    
    try:
        # Input validation
        if not date or not date.strip():
            result['error'] = 'Invalid date'
            return result
        
        if latitude < -90 or latitude > 90 or longitude < -180 or longitude > 180:
            result['error'] = 'Invalid coordinates'
            return result
        
        # Connect to database
        conn = sqlite3.connect('Sensor.db')
        cursor = conn.cursor()
        
        # Parameterized query to prevent SQL injection
        sql = "SELECT temperature FROM sensor_data WHERE latitude = ? AND longitude = ? AND date = ?"
        cursor.execute(sql, (latitude, longitude, date))
        
        row = cursor.fetchone()
        
        if row:
            result['temperature'] = row[0]
            result['success'] = True
        else:
            result['error'] = 'No data found'
            result['success'] = False
            
    except sqlite3.Error as e:
        result['error'] = f'Database error: {str(e)}'
        result['success'] = False
    finally:
        if conn:
            conn.close()
    
    return result


if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    print(temperature_for_location(40.7128, -74.0060, "2023-01-15"))
    
    print("\\nTest Case 2:")
    print(temperature_for_location(51.5074, -0.1278, "2023-02-20"))
    
    print("\\nTest Case 3:")
    print(temperature_for_location(35.6762, 139.6503, "2023-03-10"))
    
    print("\\nTest Case 4 (Invalid coordinates):")
    print(temperature_for_location(100.0, -200.0, "2023-04-05"))
    
    print("\\nTest Case 5 (Empty date):")
    print(temperature_for_location(48.8566, 2.3522, ""))
