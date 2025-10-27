import datetime

def _query_mock_database(latitude: float, longitude: float, date_str: str) -> float:
    """
    A mock database query function. In a real application, this would connect
    to a database like PostgreSQL, MySQL, etc., using a library like psycopg2 or mysql-connector-python.
    It would use parameterized queries to prevent SQL injection.
    """
    print("Connecting to database 'Sensor'...")
    print(f"Querying for latitude={latitude:.4f}, longitude={longitude:.4f}, date={date_str}")
    
    # Simple deterministic calculation for demonstration
    # In a real app, this would execute a DB query.
    base_temp = (latitude + 45.0) / 10.0  # Base temp related to latitude
    
    # A simple way to get a deterministic number from the date string
    date_hash = sum(ord(c) for c in date_str)
    daily_variation = (date_hash % 200) / 10.0 - 10.0  # Variation from -10 to +10
    
    return base_temp + daily_variation

def temperature_for_location(latitude: float, longitude: float, date: str) -> float:
    """
    Simulates an API endpoint function that retrieves temperature for a given location and date.
    It validates inputs and fetches data from a mock database.

    Args:
        latitude: The geographical latitude (-90.0 to 90.0).
        longitude: The geographical longitude (-180.0 to 180.0).
        date: The date in YYYY-MM-DD format.

    Returns:
        The temperature in Celsius.

    Raises:
        ValueError: if the inputs are invalid.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(latitude, (int, float)) or not -90.0 <= latitude <= 90.0:
        raise ValueError("Invalid latitude. Must be a number between -90.0 and 90.0.")
    
    if not isinstance(longitude, (int, float)) or not -180.0 <= longitude <= 180.0:
        raise ValueError("Invalid longitude. Must be a number between -180.0 and 180.0.")

    if not isinstance(date, str):
         raise ValueError("Invalid date. Must be a string.")
    
    # Using strptime is a robust way to validate date format and semantics
    try:
        datetime.datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        raise ValueError("Invalid date format or value. Expected YYYY-MM-DD.")

    # In a real application, database connection logic would be here.
    return _query_mock_database(latitude, longitude, date)

def main():
    """ Main function with test cases. """
    print("--- Running Test Cases ---")
    
    test_cases = [
        # (latitude, longitude, date, expected_success)
        (40.7128, -74.0060, "2023-10-27", True),  # Test 1: Valid input
        (34.0522, -118.2437, "2024-01-15", True),  # Test 2: Another valid input
        (100.0, -74.0060, "2023-10-27", False),  # Test 3: Invalid latitude
        (40.7128, -74.0060, "27-10-2023", False), # Test 4: Invalid date format
        (40.7128, -200.0, "2023-10-27", False), # Test 5: Invalid longitude
    ]

    for i, (lat, lon, dt, success) in enumerate(test_cases, 1):
        try:
            temp = temperature_for_location(lat, lon, dt)
            if success:
                print(f"Test {i} PASSED: Temperature is {temp:.2f}°C")
            else:
                print(f"Test {i} FAILED: Exception was not thrown for invalid input ({lat}, {lon}, '{dt}')")
        except ValueError as e:
            if not success:
                print(f"Test {i} PASSED: Caught expected exception: {e}")
            else:
                print(f"Test {i} FAILED: Caught unexpected exception: {e}")
        print()

if __name__ == "__main__":
    main()