# Mock database - a list of dictionaries
MOCK_DATABASE = [
    {"latitude": 40.7128, "longitude": -74.0060, "date": "2023-10-27", "temperature": 15.5},
    {"latitude": 34.0522, "longitude": -118.2437, "date": "2023-10-27", "temperature": 22.0},
    {"latitude": 48.8566, "longitude": 2.3522, "date": "2023-10-28", "temperature": 12.3},
    {"latitude": 35.6895, "longitude": 139.6917, "date": "2023-10-28", "temperature": 18.7},
]

def temperature_for_location(latitude, longitude, date):
    """
    Simulates fetching temperature for a given location and date from a database.
    In a real application, this would involve a database connection and SQL query.

    :param latitude: The latitude of the location.
    :param longitude: The longitude of the location.
    :param date: The date for the temperature reading (format YYYY-MM-DD).
    :return: The temperature as a float, or None if not found.
    """
    # Simulate "SELECT temperature FROM weather_data WHERE ..."
    for record in MOCK_DATABASE:
        if (record["latitude"] == latitude and
                record["longitude"] == longitude and
                record["date"] == date):
            return record["temperature"]
    return None  # No record found

def main():
    # 5 Test Cases
    test_cases = [
        (40.7128, -74.0060, "2023-10-27"),   # Case 1: Exists
        (34.0522, -118.2437, "2023-10-27"),  # Case 2: Exists
        (48.8566, 2.3522, "2023-10-28"),     # Case 3: Exists
        (0.0, 0.0, "2023-10-27"),            # Case 4: Does not exist
        (35.6895, 139.6917, "2023-10-29")    # Case 5: Exists but wrong date
    ]

    print("--- Python Test Cases ---")
    for i, (lat, lon, date) in enumerate(test_cases, 1):
        temp = temperature_for_location(lat, lon, date)
        print(f"Test Case {i} (Lat: {lat:.4f}, Lon: {lon:.4f}, Date: {date}): ", end="")
        if temp is not None:
            print(f"Temperature = {temp:.1f} C")
        else:
            print("Temperature data not found.")

if __name__ == "__main__":
    main()