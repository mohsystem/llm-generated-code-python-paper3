import sys
from typing import Optional, Dict, Tuple

# Simulating a database table from the "Sensor" database.
# In a real application, this would be a connection to a database.
# The key is a tuple, which is a secure way to look up composite keys.
SENSOR_DATA_TABLE: Dict[Tuple[float, float, str], float] = {
    (40.7128, -74.0060, "2023-10-27"): 15.5,
    (34.0522, -118.2437, "2023-10-27"): 22.1,
    (48.8566, 2.3522, "2023-10-26"): 12.8,
    (35.6895, 139.6917, "2023-10-27"): 18.2,
}

def temperature_for_location(latitude: float, longitude: float, date: str) -> Optional[float]:
    """
    Simulates fetching temperature for a given location and date.
    
    This function demonstrates a secure way to query data by using a tuple key for
    lookup. This is analogous to using parameterized queries (placeholders) in a
    real database connector (e.g., psycopg2, mysql-connector) to prevent SQL injection.

    A real DB implementation would look like this:
    
    query = "SELECT temperature FROM sensor_data WHERE latitude = %s AND longitude = %s AND date = %s"
    cursor.execute(query, (latitude, longitude, date))
    result = cursor.fetchone()
    
    This separates the SQL command from the user data, which is the core of preventing SQL injection.
    
    Args:
        latitude: The latitude of the location.
        longitude: The longitude of the location.
        date: The date of the reading (e.g., "2023-10-27").
        
    Returns:
        The temperature as a float if found, otherwise None.
    """
    if not isinstance(date, str) or not date.strip():
        return None
        
    # Using a tuple as a key is a safe way to perform a lookup.
    key = (latitude, longitude, date)
    return SENSOR_DATA_TABLE.get(key)

def main():
    """Main function with test cases."""
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Valid and existing data
    print("Test Case 1 (NYC):")
    temp = temperature_for_location(40.7128, -74.0060, "2023-10-27")
    print(f"  Temperature: {temp}" if temp is not None else "  Temperature not found.")

    # Test Case 2: Valid and existing data
    print("Test Case 2 (LA):")
    temp = temperature_for_location(34.0522, -118.2437, "2023-10-27")
    print(f"  Temperature: {temp}" if temp is not None else "  Temperature not found.")

    # Test Case 3: Data not found (wrong date)
    print("Test Case 3 (Paris, wrong date):")
    temp = temperature_for_location(48.8566, 2.3522, "2023-10-27")
    print(f"  Temperature: {temp}" if temp is not None else "  Temperature not found.")

    # Test Case 4: Data not found (non-existent location)
    print("Test Case 4 (London):")
    temp = temperature_for_location(51.5074, -0.1278, "2023-10-27")
    print(f"  Temperature: {temp}" if temp is not None else "  Temperature not found.")
    
    # Test Case 5: Invalid input (empty date)
    print("Test Case 5 (Invalid Input):")
    temp = temperature_for_location(35.6895, 139.6917, "  ")
    print(f"  Temperature: {temp}" if temp is not None else "  Temperature not found.")

if __name__ == "__main__":
    main()