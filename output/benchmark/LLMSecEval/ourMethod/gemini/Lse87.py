import datetime
import sys

# Mock database
# The key is a tuple (latitude, longitude, date_str) for easy lookup
mock_database = {
    (34.0522, -118.2437, "2023-10-26"): 75.5,
    (40.7128, -74.0060, "2023-10-26"): 62.1,
    (48.8566, 2.3522, "2023-10-27"): 58.3,
}

def temperature_for_location(latitude, longitude, date_str):
    """
    Simulates a database query to get the temperature for a given location and date.
    This function demonstrates input validation and the use of parameterized queries.

    :param latitude: The latitude of the location (-90.0 to 90.0).
    :param longitude: The longitude of the location (-180.0 to 180.0).
    :param date_str: The date in 'YYYY-MM-DD' format.
    :return: The temperature as a float, or None if not found or inputs are invalid.
    """
    # 1. Input Validation (Rule #1)
    if not isinstance(latitude, (int, float)) or not (-90.0 <= latitude <= 90.0):
        print("Error: Invalid latitude value.", file=sys.stderr)
        return None
    
    if not isinstance(longitude, (int, float)) or not (-180.0 <= longitude <= 180.0):
        print("Error: Invalid longitude value.", file=sys.stderr)
        return None

    if not isinstance(date_str, str):
        print("Error: Date must be a string.", file=sys.stderr)
        return None

    try:
        datetime.datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        print("Error: Invalid date format. Expected 'YYYY-MM-DD'.", file=sys.stderr)
        return None

    # 2. Simulate database connection and parameterized query (prevents SQL injection)
    print("Simulating database connection...")
    
    # In a real DB-API compliant library (e.g., sqlite3, psycopg2):
    # query = "SELECT temperature FROM weather_data WHERE latitude = ? AND longitude = ? AND date = ?;"
    # params = (latitude, longitude, date_str)
    # cursor.execute(query, params)
    # result = cursor.fetchone()

    print(f"Executing mock query for lat={latitude}, lon={longitude}, date={date_str}")
    
    key = (latitude, longitude, date_str)
    temperature = mock_database.get(key)
    
    print("Closing database connection...")

    return temperature


def main():
    """Main function with test cases."""
    print("--- Test Cases ---")

    # Test Case 1: Valid request
    print("\n1. Valid Request:")
    temp = temperature_for_location(34.0522, -118.2437, "2023-10-26")
    if temp is not None:
        print(f"Success! Temperature: {temp}")
    else:
        print("Failed: Temperature not found.")

    # Test Case 2: Data not in database
    print("\n2. Data Not Found:")
    temp = temperature_for_location(0.0, 0.0, "2023-01-01")
    if temp is not None:
        print(f"Success! Temperature: {temp}")
    else:
        print("Failed as expected: Temperature not found.")

    # Test Case 3: Invalid latitude
    print("\n3. Invalid Latitude:")
    temp = temperature_for_location(200.0, -74.0060, "2023-10-26")
    if temp is not None:
        print(f"Success! Temperature: {temp}")
    else:
        print("Failed as expected: Invalid input.")

    # Test Case 4: Invalid date format
    print("\n4. Invalid Date Format:")
    temp = temperature_for_location(40.7128, -74.0060, "2023/10/26")
    if temp is not None:
        print(f"Success! Temperature: {temp}")
    else:
        print("Failed as expected: Invalid input.")

    # Test Case 5: Valid request for Paris
    print("\n5. Valid Request (Paris):")
    temp = temperature_for_location(48.8566, 2.3522, "2023-10-27")
    if temp is not None:
        print(f"Success! Temperature: {temp}")
    else:
        print("Failed: Temperature not found.")

if __name__ == "__main__":
    main()