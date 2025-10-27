
import sqlite3
from datetime import datetime
from typing import Optional

# Maximum allowed values to prevent resource exhaustion
MAX_LATITUDE = 90.0
MIN_LATITUDE = -90.0
MAX_LONGITUDE = 180.0
MIN_LONGITUDE = -180.0

def temperature_for_location(latitude: str, longitude: str, date: str) -> str:
    """\n    Retrieves temperature for a given location and date.\n    Uses parameterized queries to prevent SQL injection.\n    Validates all inputs before processing.\n    \n    Args:\n        latitude: The latitude coordinate as string\n        longitude: The longitude coordinate as string\n        date: The date in ISO format (YYYY-MM-DD)\n    \n    Returns:\n        Temperature value as string or error message\n    """
    # Input validation: Check for None or empty inputs
    if not latitude or not isinstance(latitude, str) or not latitude.strip():
        return "Error: Invalid latitude parameter"
    if not longitude or not isinstance(longitude, str) or not longitude.strip():
        return "Error: Invalid longitude parameter"
    if not date or not isinstance(date, str) or not date.strip():
        return "Error: Invalid date parameter"
    
    try:
        # Input validation: Parse and validate latitude
        lat = float(latitude.strip())
        if lat < MIN_LATITUDE or lat > MAX_LATITUDE:
            return "Error: Latitude out of valid range"
        
        # Input validation: Parse and validate longitude
        lon = float(longitude.strip())
        if lon < MIN_LONGITUDE or lon > MAX_LONGITUDE:
            return "Error: Longitude out of valid range"
        
        # Input validation: Parse and validate date format (YYYY-MM-DD)
        parsed_date = datetime.strptime(date.strip(), "%Y-%m-%d").date()
        
    except ValueError:
        # Do not leak internal details in error messages
        return "Error: Invalid input format"
    
    conn = None
    cursor = None
    
    try:
        # Connect to database (using SQLite for demonstration)
        # In production, use postgresql with ssl context
        conn = sqlite3.connect('weather.db', timeout=10.0)
        
        # Set row factory for easier access
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        # The ? placeholders ensure user input is properly escaped
        query = """\n            SELECT temperature \n            FROM weather_data \n            WHERE latitude = ? AND longitude = ? AND date = ?\n            LIMIT 1\n        """
        
        # Execute with parameters - database driver handles proper escaping
        cursor.execute(query, (lat, lon, str(parsed_date)))
        
        # Fetch result
        row = cursor.fetchone()
        
        if row:
            temperature = row['temperature']
            return f"{temperature:.2f}"
        else:
            return "Error: No data found for given parameters"
            
    except sqlite3.Error as e:
        # Log detailed error internally but return generic message
        print(f"Database error: {str(e)}", file=__import__('sys').stderr)
        return "Error: Database operation failed"
    except Exception as e:
        # Catch any unexpected errors
        print(f"Unexpected error: {str(e)}", file=__import__('sys').stderr)
        return "Error: Operation failed"
    finally:
        # Ensure all resources are closed properly
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def main():
    """Test cases for temperature_for_location function"""
    # Test case 1: Valid input
    print("Test 1:", temperature_for_location("40.7128", "-74.0060", "2024-01-15"))
    
    # Test case 2: Invalid latitude (out of range)
    print("Test 2:", temperature_for_location("95.0", "-74.0060", "2024-01-15"))
    
    # Test case 3: Invalid date format
    print("Test 3:", temperature_for_location("40.7128", "-74.0060", "01/15/2024"))
    
    # Test case 4: None input
    print("Test 4:", temperature_for_location(None, "-74.0060", "2024-01-15"))
    
    # Test case 5: SQL injection attempt (safely handled by parameterized query)
    print("Test 5:", temperature_for_location("40.7128' OR '1'='1", "-74.0060", "2024-01-15"))


if __name__ == "__main__":
    main()
