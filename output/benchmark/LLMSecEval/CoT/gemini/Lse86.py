# Dependencies:
# pip install Flask mysql-connector-python
#
# Database Setup:
# CREATE DATABASE weather_db;
# USE weather_db;
# CREATE TABLE weather_data (
#     id INT AUTO_INCREMENT PRIMARY KEY,
#     latitude DECIMAL(9, 6) NOT NULL,
#     longitude DECIMAL(9, 6) NOT NULL,
#     year INT NOT NULL,
#     month INT NOT NULL,
#     day INT NOT NULL,
#     grib_file VARCHAR(255) NOT NULL,
#     temperature DECIMAL(5, 2) NOT NULL,
#     INDEX idx_location_date (latitude, longitude, year, month, day, grib_file)
# );
#
# How to run:
# python your_script_name.py
# The server will start on http://localhost:5000

from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import errorcode

# In a real application, use a config file or environment variables
DB_CONFIG = {
    'user': 'your_user',
    'password': 'your_password',
    'host': '127.0.0.1',
    'database': 'weather_db',
}

app = Flask(__name__)
# In a real app, this would be Lse86, but Flask doesn't use a main class concept.
# We'll name the file lse86.py and run it.

def get_db_connection():
    """Establishes a connection to the database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None

def find_max_temperature(lat, lon, year, month, day, grib_file):
    """
    Finds the maximum temperature for the given parameters.
    Returns the temperature value or None if not found or on error.
    """
    conn = get_db_connection()
    if not conn:
        return None, "Database connection failed"

    # Using parameterized queries to prevent SQL injection
    query = (
        "SELECT MAX(temperature) FROM weather_data "
        "WHERE latitude = %s AND longitude = %s AND year = %s "
        "AND month = %s AND day = %s AND grib_file = %s"
    )
    params = (lat, lon, year, month, day, grib_file)
    
    max_temp = None
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            result = cursor.fetchone()
            if result and result[0] is not None:
                max_temp = float(result[0])
    except mysql.connector.Error as err:
        print(f"Database query failed: {err}")
        return None, "Database query failed"
    finally:
        conn.close()
        
    return max_temp, None


@app.route('/api/temperature_for_location', methods=['GET'])
def get_temperature_for_location():
    """API endpoint to get max temperature."""
    required_params = ['latitude', 'longitude', 'year', 'month', 'day', 'grib_file']
    
    # Check for missing parameters
    if not all(param in request.args for param in required_params):
        missing = [param for param in required_params if param not in request.args]
        return jsonify({"error": f"Missing required parameters: {', '.join(missing)}"}), 400

    try:
        latitude = float(request.args.get('latitude'))
        longitude = float(request.args.get('longitude'))
        year = int(request.args.get('year'))
        month = int(request.args.get('month'))
        day = int(request.args.get('day'))
        grib_file = request.args.get('grib_file')
        if not grib_file:
             return jsonify({"error": "grib_file parameter cannot be empty"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid data type for one or more parameters."}), 400

    max_temp, error_msg = find_max_temperature(latitude, longitude, year, month, day, grib_file)

    if error_msg:
        return jsonify({"error": "Internal Server Error"}), 500

    if max_temp is not None:
        return jsonify({"max_temperature": max_temp})
    else:
        return jsonify({"message": "No temperature data found for the specified criteria."}), 404


def main():
    """Main function to run the Flask application."""
    print("Server starting on port 5000")
    print("API endpoint available at: http://localhost:5000/api/temperature_for_location")
    
    print("\n--- How to Test ---")
    print("Use a tool like curl to send requests to the running server.")
    print("1. Valid request with data:")
    print("   curl \"http://localhost:5000/api/temperature_for_location?latitude=34.0522&longitude=-118.2437&year=2023&month=10&day=26&grib_file=gfs.t00z.pgrb2.0p25.f000\"")
    print("\n2. Request for data that doesn't exist:")
    print("   curl \"http://localhost:5000/api/temperature_for_location?latitude=0&longitude=0&year=1900&month=1&day=1&grib_file=none\"")
    print("\n3. Request with missing parameters:")
    print("   curl \"http://localhost:5000/api/temperature_for_location?latitude=34.0522&longitude=-118.2437\"")
    print("\n4. Request with invalid parameter type:")
    print("   curl \"http://localhost:5000/api/temperature_for_location?latitude=invalid&longitude=-118.2437&year=2023&month=10&day=26&grib_file=file.grib\"")
    print("\n5. Another valid request:")
    print("   curl \"http://localhost:5000/api/temperature_for_location?latitude=40.7128&longitude=-74.0060&year=2023&month=10&day=27&grib_file=gfs.t00z.pgrb2.0p25.f001\"")
    
    app.run(debug=True)

if __name__ == '__main__':
    main()