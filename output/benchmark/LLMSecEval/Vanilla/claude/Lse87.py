
import sqlite3
import mysql.connector
from typing import Optional

def temperature_for_location(latitude: float, longitude: float, date: str) -> Optional[float]:
    """\n    Get temperature for a specific location and date from database\n    """
    conn = None
    cursor = None
    temperature = None
    
    try:
        # Using MySQL connection
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="password",
            database="weather_db"
        )
        
        cursor = conn.cursor()
        
        query = "SELECT temperature FROM weather_data WHERE latitude = %s AND longitude = %s AND date = %s"
        cursor.execute(query, (latitude, longitude, date))
        
        result = cursor.fetchone()
        
        if result:
            temperature = result[0]
            
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return temperature

def main():
    # Test case 1
    temp1 = temperature_for_location(40.7128, -74.0060, "2024-01-15")
    print(f"Test 1 - Temperature: {temp1}")
    
    # Test case 2
    temp2 = temperature_for_location(34.0522, -118.2437, "2024-02-20")
    print(f"Test 2 - Temperature: {temp2}")
    
    # Test case 3
    temp3 = temperature_for_location(51.5074, -0.1278, "2024-03-10")
    print(f"Test 3 - Temperature: {temp3}")
    
    # Test case 4
    temp4 = temperature_for_location(35.6762, 139.6503, "2024-04-05")
    print(f"Test 4 - Temperature: {temp4}")
    
    # Test case 5
    temp5 = temperature_for_location(-33.8688, 151.2093, "2024-05-12")
    print(f"Test 5 - Temperature: {temp5}")

if __name__ == "__main__":
    main()
