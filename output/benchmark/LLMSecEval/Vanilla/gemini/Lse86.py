# NOTE:
# 1. This code requires the Flask and mysql-connector-python libraries.
#    Install them using pip:
#    pip install Flask mysql-connector-python
#
# 2. Before running, set up a MySQL database with the following table and credentials.
#    - Database: weatherdb
#    - User:     weather_user
#    - Password: password
#    - Table:
#      CREATE TABLE weather_data (
#          id INT AUTO_INCREMENT PRIMARY KEY,
#          latitude DECIMAL(9, 6) NOT NULL,
#          longitude DECIMAL(9, 6) NOT NULL,
#          year INT NOT NULL,
#          month INT NOT NULL,
#          day INT NOT NULL,
#          grib_file VARCHAR(255) NOT NULL,
#          temperature DECIMAL(5, 2) NOT NULL
#      );
#      -- Add some sample data to the table for testing.
#      INSERT INTO weather_data (latitude, longitude, year, month, day, grib_file, temperature) VALUES
#      (34.05, -118.24, 2023, 7, 15, 'gfs.t00z.pgrb2.0p25.f000', 29.5),
#      (34.05, -118.24, 2023, 7, 15, 'gfs.t00z.pgrb2.0p25.f000', 31.2),
#      (40.71, -74.00, 2023, 8, 20, 'gfs.t06z.pgrb2.0p25.f001', 25.0),
#      (48.85, 2.35, 2024, 1, 10, 'era5.12z.an.sfc', 5.5),
#      (48.85, 2.35, 2024, 1, 10, 'era5.12z.an.sfc', 6.1);

from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

# --- DATABASE CONFIGURATION ---
DB_CONFIG = {
    'host': 'localhost',
    'database': 'weatherdb',
    'user': 'weather_user',
    'password': 'password'
}

def get_max_temperature(lat, lon, year, month, day, grib_file):
    """
    Connects to the MySQL database and retrieves the max temperature.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        if conn.is_connected():
            cursor = conn.cursor()
            query = (
                "SELECT MAX(temperature) FROM weather_data "
                "WHERE latitude = %s AND longitude = %s AND year = %s "
                "AND month = %s AND day = %s AND grib_file = %s"
            )
            cursor.execute(query, (lat, lon, year, month, day, grib_file))
            result = cursor.fetchone()
            
            if result and result[0] is not None:
                return {"max_temperature": float(result[0])}, 200
            else:
                return {"message": "Temperature data not found for the given criteria."}, 404
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return {"error": f"Database error: {e}"}, 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
    return {"error": "An unknown error occurred"}, 500


@app.route('/api/temperature_for_location', methods=['GET'])
def temperature_for_location():
    """
    API endpoint to get the maximum temperature for a location and date.
    """
    required_params = ['latitude', 'longitude', 'year', 'month', 'day', 'grib_file']
    if not all(param in request.args for param in required_params):
        return jsonify({"error": "Bad Request: Missing required parameters."}), 400

    try:
        lat = float(request.args.get('latitude'))
        lon = float(request.args.get('longitude'))
        year = int(request.args.get('year'))
        month = int(request.args.get('month'))
        day = int(request.args.get('day'))
        grib_file = request.args.get('grib_file')
    except (ValueError, TypeError):
        return jsonify({"error": "Bad Request: Invalid data type for a parameter."}), 400

    result, status_code = get_max_temperature(lat, lon, year, month, day, grib_file)
    return jsonify(result), status_code

def run_app():
    """ Main function to run the Flask app and show test cases """
    port = 8080
    print(f"Server starting on port {port}")
    print("--- 5 Test Cases (run in a separate terminal) ---")
    print(f"1. curl \"http://localhost:{port}/api/temperature_for_location?latitude=34.05&longitude=-118.24&year=2023&month=7&day=15&grib_file=gfs.t00z.pgrb2.0p25.f000\"")
    print(f"2. curl \"http://localhost:{port}/api/temperature_for_location?latitude=40.71&longitude=-74.00&year=2023&month=8&day=20&grib_file=gfs.t06z.pgrb2.0p25.f001\"")
    print(f"3. curl \"http://localhost:{port}/api/temperature_for_location?latitude=48.85&longitude=2.35&year=2024&month=1&day=10&grib_file=era5.12z.an.sfc\"")
    print(f"4. curl \"http://localhost:{port}/api/temperature_for_location?latitude=99.99&longitude=99.99&year=2025&month=1&day=1&grib_file=none\" # Should return not found")
    print(f"5. curl \"http://localhost:{port}/api/temperature_for_location?latitude=40.71\" # Should return bad request")
    
    # Use host='0.0.0.0' to make it accessible from outside the container
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    run_app()