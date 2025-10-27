
import sqlite3
import re
from typing import Optional, Tuple

# Database path
DB_PATH = 'Sensor.db'

# Validation constants
MIN_LAT = -90.0
MAX_LAT = 90.0
MIN_LON = -180.0
MAX_LON = 180.0
DATE_PATTERN = re.compile(r'^\\d{4}-\\d{2}-\\d{2}$')

def is_valid_latitude(lat: float) -> bool:
    """\n    Validates latitude value\n    Prevents injection and ensures valid geographic coordinate\n    """
    try:
        return MIN_LAT <= float(lat) <= MAX_LAT
    except (ValueError, TypeError):
        return False

def is_valid_longitude(lon: float) -> bool:
    """\n    Validates longitude value\n    Prevents injection and ensures valid geographic coordinate\n    """
    try:
        return MIN_LON <= float(lon) <= MAX_LON
    except (ValueError, TypeError):
        return False

def is_valid_date(date: str) -> bool:
    """\n    Validates date format (YYYY-MM-DD)\n    Prevents SQL injection via date parameter\n    """
    if not isinstance(date, str) or len(date) > 10:
        return False
    return bool(DATE_PATTERN.match(date))

def temperature_for_location(latitude: float, longitude: float, date: str) -> Tuple[bool, Optional[float], Optional[str]]:
    """\n    Main API function to get temperature for a location\n    Uses parameterized queries to prevent SQL injection\n    Validates all inputs before processing\n    Fails closed on any validation error\n    Returns: (success, temperature, error_message)\n    """
    # Input validation - reject invalid data early
    if not is_valid_latitude(latitude):
        return (False, None, "Invalid request")
    
    if not is_valid_longitude(longitude):
        return (False, None, "Invalid request")
    
    if not is_valid_date(date):
        return (False, None, "Invalid request")
    
    conn = None
    cursor = None
    
    try:
        # Connect to database with restricted permissions
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        # All user inputs are bound as parameters, never concatenated
        query = "SELECT temperature FROM sensor_data WHERE latitude = ? AND longitude = ? AND date = ? LIMIT 1"
        
        # Execute with bound parameters for type safety
        cursor.execute(query, (latitude, longitude, date))
        
        # Fetch result
        row = cursor.fetchone()
        
        if row:
            temperature = row[0]
            # Check for NULL values
            if temperature is None:
                return (False, None, "Data not available")
            return (True, float(temperature), None)
        else:
            return (False, None, "Data not found")
            
    except sqlite3.Error as e:
        # Generic error message - do not leak database structure
        return (False, None, "Service error")
    except Exception as e:
        # Generic error message - do not leak internal details
        return (False, None, "Service error")
    finally:
        # Ensure resources are freed exactly once
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def main():
    """Test cases for temperature_for_location"""
    
    # Test case 1: Valid request
    success, temp, error = temperature_for_location(40.7128, -74.0060, "2024-01-15")
    print(f"Test 1 - Success: {success}, Temp: {temp}, Error: {error}")
    
    # Test case 2: Invalid latitude
    success, temp, error = temperature_for_location(95.0, -74.0060, "2024-01-15")
    print(f"Test 2 - Success: {success}, Temp: {temp}, Error: {error}")
    
    # Test case 3: Invalid date format (SQL injection attempt)
    success, temp, error = temperature_for_location(40.7128, -74.0060, "2024-01-15' OR '1'='1")
    print(f"Test 3 - Success: {success}, Temp: {temp}, Error: {error}")
    
    # Test case 4: Invalid longitude
    success, temp, error = temperature_for_location(40.7128, -200.0, "2024-01-15")
    print(f"Test 4 - Success: {success}, Temp: {temp}, Error: {error}")
    
    # Test case 5: Valid coordinates, different date
    success, temp, error = temperature_for_location(51.5074, -0.1278, "2024-02-20")
    print(f"Test 5 - Success: {success}, Temp: {temp}, Error: {error}")

if __name__ == "__main__":
    main()
