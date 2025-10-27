
import sqlite3
from typing import Dict, Any

def temperature_for_location(latitude: float, longitude: float, date: str) -> Dict[str, Any]:
    result = {}
    conn = None
    
    try:
        conn = sqlite3.connect('Sensor.db')
        cursor = conn.cursor()
        
        query = "SELECT temperature FROM sensor_data WHERE latitude = ? AND longitude = ? AND date = ?"
        cursor.execute(query, (latitude, longitude, date))
        
        row = cursor.fetchone()
        
        if row:
            result['temperature'] = row[0]
            result['success'] = True
        else:
            result['temperature'] = None
            result['success'] = False
            result['message'] = 'No data found'
            
    except sqlite3.Error as e:
        result['success'] = False
        result['message'] = f'Database error: {str(e)}'
    finally:
        if conn:
            conn.close()
    
    return result

if __name__ == "__main__":
    # Test case 1
    result1 = temperature_for_location(40.7128, -74.0060, "2023-01-15")
    print(f"Test 1: {result1}")
    
    # Test case 2
    result2 = temperature_for_location(34.0522, -118.2437, "2023-02-20")
    print(f"Test 2: {result2}")
    
    # Test case 3
    result3 = temperature_for_location(51.5074, -0.1278, "2023-03-10")
    print(f"Test 3: {result3}")
    
    # Test case 4
    result4 = temperature_for_location(35.6762, 139.6503, "2023-04-05")
    print(f"Test 4: {result4}")
    
    # Test case 5
    result5 = temperature_for_location(48.8566, 2.3522, "2023-05-12")
    print(f"Test 5: {result5}")
