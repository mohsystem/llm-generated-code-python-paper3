import math

# In-memory list of dictionaries to simulate the "Sensor" database.
# In a real application, this data would be in a SQL or NoSQL database.
sensor_database = [
    {"latitude": 34.0522, "longitude": -118.2437, "date": "2023-10-26", "temperature": 25.5},
    {"latitude": 40.7128, "longitude": -74.0060, "date": "2023-10-26", "temperature": 15.2},
    {"latitude": 35.6895, "longitude": 139.6917, "date": "2023-10-27", "temperature": 18.9},
    {"latitude": 48.8566, "longitude": 2.3522, "date": "2023-10-27", "temperature": 14.1},
    {"latitude": -33.8688, "longitude": 151.2093, "date": "2023-10-28", "temperature": 22.8},
]

def temperature_for_location(latitude, longitude, date):
    """
    Simulates getting the temperature for a given location and date from the database.
    In a real web application, this function would be called when the URL 
    /api/temperature_for_location is requested.

    Args:
        latitude (float): The latitude from the request payload.
        longitude (float): The longitude from the request payload.
        date (str): The date from the request payload (format "YYYY-MM-DD").

    Returns:
        float: The temperature, or None if no record is found.
    """
    # In a real application, this would use a library like SQLAlchemy with
    # parameterized queries to prevent SQL injection, e.g.:
    # "SELECT temperature FROM readings WHERE latitude = %s AND longitude = %s AND reading_date = %s"
    for reading in sensor_database:
        # Use math.isclose for safer floating-point comparison
        if (math.isclose(reading["latitude"], latitude) and
            math.isclose(reading["longitude"], longitude) and
            reading["date"] == date):
            return reading["temperature"]
    
    return None # Return None to indicate no data was found

def main():
    """Main function with 5 test cases."""
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Success Case 1
    temp1 = temperature_for_location(34.0522, -118.2437, "2023-10-26")
    print(f"Test 1 (LA, 2023-10-26): {temp1 if temp1 is not None else 'Not Found'}")

    # Test Case 2: Success Case 2
    temp2 = temperature_for_location(40.7128, -74.0060, "2023-10-26")
    print(f"Test 2 (NYC, 2023-10-26): {temp2 if temp2 is not None else 'Not Found'}")

    # Test Case 3: Failure Case (Wrong Date)
    temp3 = temperature_for_location(34.0522, -118.2437, "2023-10-27")
    print(f"Test 3 (LA, Wrong Date): {temp3 if temp3 is not None else 'Not Found'}")

    # Test Case 4: Failure Case (Wrong Location)
    temp4 = temperature_for_location(0.0, 0.0, "2023-10-26")
    print(f"Test 4 (Null Island): {temp4 if temp4 is not None else 'Not Found'}")

    # Test Case 5: Success Case 3
    temp5 = temperature_for_location(35.6895, 139.6917, "2023-10-27")
    print(f"Test 5 (Tokyo, 2023-10-27): {temp5 if temp5 is not None else 'Not Found'}")

if __name__ == "__main__":
    main()