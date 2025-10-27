import sqlite3

def setup_database(conn):
    """Sets up an in-memory database and populates it with test data."""
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE weather_data (
            id INTEGER PRIMARY KEY,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            aqi_date TEXT NOT NULL,
            temperature REAL NOT NULL,
            UNIQUE(latitude, longitude, aqi_date)
        )
    ''')
    test_data = [
        (40.71, -74.00, '2023-10-26', 15.5),
        (34.05, -118.24, '2023-10-26', 22.0),
        (48.85, 2.35, '2023-10-27', 12.3),
        (35.68, 139.69, '2023-10-27', 18.1)
    ]
    cursor.executemany('''
        INSERT INTO weather_data (latitude, longitude, aqi_date, temperature)
        VALUES (?, ?, ?, ?)
    ''', test_data)
    conn.commit()
    print("In-memory SQLite database created and populated for testing.")

def temperature_for_location(db_connection, latitude: float, longitude: float, date: str) -> float | None:
    """
    Connects to a database and securely queries for the temperature
    at a given latitude, longitude, and date.
    
    Args:
        db_connection: A database connection object.
        latitude: The latitude of the location.
        longitude: The longitude of the location.
        date: The date for the temperature reading (e.g., "YYYY-MM-DD").
        
    Returns:
        The temperature as a float, or None if not found.
    """
    cursor = db_connection.cursor()
    
    # The SQL query with '?' placeholders to prevent SQL injection.
    # The sqlite3 library will safely substitute the values.
    sql = "SELECT temperature FROM weather_data WHERE latitude = ? AND longitude = ? AND aqi_date = ?"
    
    print(f"\n--- Python/sqlite3 Secure Pattern Demonstration ---")
    print(f"Executing query: {sql}")
    print(f"With parameters: ({latitude}, {longitude}, '{date}')")

    try:
        cursor.execute(sql, (latitude, longitude, date))
        result = cursor.fetchone()
        
        if result:
            return result[0]
        else:
            return None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

def main():
    """Main function with 5 test cases."""
    # Use an in-memory SQLite database for this self-contained example
    conn = sqlite3.connect(":memory:")
    setup_database(conn)

    print("\n--- Running 5 Test Cases ---")
    
    # Test Case 1: Valid and existing data
    temp1 = temperature_for_location(conn, 40.71, -74.00, "2023-10-26")
    print(f"Result 1: {temp1 if temp1 is not None else 'Not Found'}")

    # Test Case 2: Valid and existing data
    temp2 = temperature_for_location(conn, 48.85, 2.35, "2023-10-27")
    print(f"Result 2: {temp2 if temp2 is not None else 'Not Found'}")

    # Test Case 3: Data that does not exist
    temp3 = temperature_for_location(conn, 0.0, 0.0, "2000-01-01")
    print(f"Result 3: {temp3 if temp3 is not None else 'Not Found'}")

    # Test Case 4: Malicious-looking input (which is safely handled by parameterized queries)
    temp4 = temperature_for_location(conn, 0, 0, "2023-10-27' OR '1'='1")
    print(f"Result 4: {temp4 if temp4 is not None else 'Not Found'}")

    # Test Case 5: Another valid case
    temp5 = temperature_for_location(conn, 35.68, 139.69, "2023-10-27")
    print(f"Result 5: {temp5 if temp5 is not None else 'Not Found'}")
    
    conn.close()

if __name__ == "__main__":
    main()