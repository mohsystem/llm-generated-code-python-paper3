# Simulating a database table called 'Sensor' in memory
sensor_database = {
    # Key is "latitude:longitude:date"
    "34.0522:-118.2437:2023-10-26": 25.5,
    "40.7128:-74.0060:2023-10-26": 15.2,
    "48.8566:2.3522:2023-10-27": 12.8,
    "35.6895:139.6917:2023-10-26": 18.0,
    "-33.8688:151.2093:2023-10-28": 22.3,
}

def temperature_for_location(latitude: float, longitude: float, date: str):
    """
    This function simulates an API endpoint call.
    It connects to the 'database' and gets the temperature for the given location and date.
    
    Args:
        latitude: The latitude of the location.
        longitude: The longitude of the location.
        date: The date in "YYYY-MM-DD" format.
        
    Returns:
        The temperature as a float if found, otherwise None.
    """
    key = f"{latitude:.4f}:{longitude:.4f}:{date}"
    return sensor_database.get(key)

# Main block to run test cases
if __name__ == "__main__":
    # --- 5 Test Cases ---

    # Test Case 1: Existing data
    print("Test Case 1: (LA, 2023-10-26)")
    temp1 = temperature_for_location(34.0522, -118.2437, "2023-10-26")
    if temp1 is not None:
        print(f"  -> Temperature: {temp1}")
    else:
        print("  -> Temperature not found.")
        
    # Test Case 2: Existing data
    print("\nTest Case 2: (NYC, 2023-10-26)")
    temp2 = temperature_for_location(40.7128, -74.0060, "2023-10-26")
    if temp2 is not None:
        print(f"  -> Temperature: {temp2}")
    else:
        print("  -> Temperature not found.")
        
    # Test Case 3: Existing data
    print("\nTest Case 3: (Paris, 2023-10-27)")
    temp3 = temperature_for_location(48.8566, 2.3522, "2023-10-27")
    if temp3 is not None:
        print(f"  -> Temperature: {temp3}")
    else:
        print("  -> Temperature not found.")

    # Test Case 4: Non-existing date
    print("\nTest Case 4: (Tokyo, Non-existing date)")
    temp4 = temperature_for_location(35.6895, 139.6917, "2023-10-27")
    if temp4 is not None:
        print(f"  -> Temperature: {temp4}")
    else:
        print("  -> Temperature not found.")
        
    # Test Case 5: Non-existing location
    print("\nTest Case 5: (Non-existing location)")
    temp5 = temperature_for_location(0.0, 0.0, "2023-10-26")
    if temp5 is not None:
        print(f"  -> Temperature: {temp5}")
    else:
        print("  -> Temperature not found.")