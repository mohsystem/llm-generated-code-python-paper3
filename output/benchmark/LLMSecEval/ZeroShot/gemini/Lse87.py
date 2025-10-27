import datetime

# This dictionary simulates a database table 'temperatures'.
# In a real Python web application (e.g., Flask, Django), you would use an ORM
# or a database connector like psycopg2 or mysql-connector-python.
temperature_database = {
    "40.7128,-74.0060,2023-10-27": 15.5,
    "34.0522,-118.2437,2023-10-27": 22.1,
    "48.8566,2.3522,2023-10-26": 12.8,
}

def temperature_for_location(latitude: float, longitude: float, date_str: str):
    """
    Securely retrieves temperature for a given location and date.
    This function simulates a web API endpoint handler.

    Args:
        latitude: The latitude of the location (-90 to 90).
        longitude: The longitude of the location (-180 to 180).
        date_str: The date in 'YYYY-MM-DD' format.

    Returns:
        The temperature as a float, or None if not found or an error occurs.
    """
    # 1. **Input Validation**: Crucial security step to prevent invalid data processing.
    if not -90.0 <= latitude <= 90.0:
        print("Error: Invalid latitude value.", file=sys.stderr)
        return None
    if not -180.0 <= longitude <= 180.0:
        print("Error: Invalid longitude value.", file=sys.stderr)
        return None
    try:
        datetime.datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        print("Error: Invalid date format. Please use YYYY-MM-DD.", file=sys.stderr)
        return None

    # 2. **Secure Database Query (Demonstration)**
    # In a real application, ALWAYS use parameterized queries to prevent SQL Injection.
    # The database driver will handle escaping the values correctly.
    #
    # --- START OF SECURE DB-API (e.g., sqlite3) EXAMPLE ---
    # import sqlite3
    # conn = sqlite3.connect('weather.db')
    # cursor = conn.cursor()
    #
    # secure_query = "SELECT temperature FROM temperatures WHERE latitude = ? AND longitude = ? AND date = ?;"
    #
    # # The '?' are placeholders. The values are passed as a tuple.
    # # This is the safe, parameterized way.
    # cursor.execute(secure_query, (latitude, longitude, date_str))
    #
    # result = cursor.fetchone()
    # conn.close()
    #
    # if result:
    #     return result[0]
    # else:
    #     return None
    # --- END OF SECURE DB-API EXAMPLE ---

    # **Simulating the secure database lookup using our dictionary**
    db_key = f"{latitude:.4f},{longitude:.4f},{date_str}"
    return temperature_database.get(db_key)

if __name__ == "__main__":
    import sys
    print("--- Running Python Test Cases ---")

    # Test Case 1: Valid request, data exists
    print("Test Case 1 (Success):")
    temp = temperature_for_location(40.7128, -74.0060, "2023-10-27")
    print(f"  Temperature: {temp}" if temp is not None else "  Temperature not found.")

    # Test Case 2: Valid request, data does not exist
    print("\nTest Case 2 (Not Found):")
    temp = temperature_for_location(10.0, 20.0, "2023-01-01")
    print(f"  Temperature: {temp}" if temp is not None else "  Temperature not found.")

    # Test Case 3: Invalid latitude
    print("\nTest Case 3 (Invalid Latitude):")
    temp = temperature_for_location(100.0, -74.0060, "2023-10-27")
    print(f"  Temperature: {temp}" if temp is not None else "  Request failed as expected.")

    # Test Case 4: Invalid longitude
    print("\nTest Case 4 (Invalid Longitude):")
    temp = temperature_for_location(40.7128, -200.0, "2023-10-27")
    print(f"  Temperature: {temp}" if temp is not None else "  Request failed as expected.")

    # Test Case 5: Invalid date format
    print("\nTest Case 5 (Invalid Date):")
    temp = temperature_for_location(34.0522, -118.2437, "27-10-2023")
    print(f"  Temperature: {temp}" if temp is not None else "  Request failed as expected.")