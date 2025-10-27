import os
import re
from datetime import date
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import errorcode

app = Flask(__name__)

# Regex to validate grib_file format. Allows alphanumeric, underscore, hyphen, and period.
GRIB_FILE_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
MAX_GRIB_FILE_LENGTH = 255

def get_db_connection():
    """Establishes a connection to the database."""
    try:
        db_user = os.environ.get("DB_USER")
        db_pass = os.environ.get("DB_PASS")
        db_host = os.environ.get("DB_HOST", "localhost")
        db_port = os.environ.get("DB_PORT", "3306")
        db_name = os.environ.get("DB_NAME", "weather_db")

        if not db_user or not db_pass:
            raise ValueError("DB_USER and DB_PASS environment variables must be set.")

        conn = mysql.connector.connect(
            user=db_user,
            password=db_pass,
            host=db_host,
            port=db_port,
            database=db_name,
            use_pure=False # Use C-extension for better performance
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

@app.route('/api/temperature_for_location', methods=['GET'])
def get_temperature():
    """
    API endpoint to get the maximum temperature for a given location and time.
    """
    try:
        # Extract and validate parameters
        latitude = float(request.args.get('latitude'))
        if not -90.0 <= latitude <= 90.0:
            return jsonify({"error": "Invalid latitude value. Must be between -90 and 90."}), 400

        longitude = float(request.args.get('longitude'))
        if not -180.0 <= longitude <= 180.0:
            return jsonify({"error": "Invalid longitude value. Must be between -180 and 180."}), 400

        year = int(request.args.get('year'))
        month = int(request.args.get('month'))
        day = int(request.args.get('day'))
        
        # Validate date
        date(year, month, day)

        grib_file = request.args.get('grib_file')
        if not grib_file:
            return jsonify({"error": "Missing grib_file parameter."}), 400
        if len(grib_file) > MAX_GRIB_FILE_LENGTH:
            return jsonify({"error": "grib_file exceeds maximum length."}), 400
        if not GRIB_FILE_PATTERN.match(grib_file):
            return jsonify({"error": "Invalid grib_file format."}), 400

    except (ValueError, TypeError):
        return jsonify({"error": "Invalid or missing required parameter(s)."}), 400
    except Exception as e: # Catches invalid date errors from date()
        return jsonify({"error": f"Invalid date: {e}"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Could not connect to the database."}), 500
        
        cursor = conn.cursor(prepared=True)
        
        query = ("SELECT MAX(temperature) FROM weather_data "
                 "WHERE latitude = %s AND longitude = %s AND year = %s AND "
                 "month = %s AND day = %s AND grib_file = %s")
        
        params = (latitude, longitude, year, month, day, grib_file)
        
        cursor.execute(query, params)
        result = cursor.fetchone()
        
        if result and result[0] is not None:
            return jsonify({"max_temperature": float(result[0])})
        else:
            return jsonify({"message": "No temperature data found for the given parameters."}), 404

    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

if __name__ == '__main__':
    print("Server starting on port 8080...")
    print("Use 'curl' to test the endpoint. Examples:")
    print("1. Success: curl \"http://localhost:8080/api/temperature_for_location?latitude=34.0522&longitude=-118.2437&year=2023&month=10&day=26&grib_file=gfs.t00z.pgrb2.0p25.f000\"")
    print("2. Invalid Latitude: curl \"http://localhost:8080/api/temperature_for_location?latitude=999&longitude=-118.2437&year=2023&month=10&day=26&grib_file=file.grib\"")
    print("3. Invalid Date: curl \"http://localhost:8080/api/temperature_for_location?latitude=40.7128&longitude=-74.0060&year=2023&month=13&day=27&grib_file=file.grib\"")
    print("4. Invalid Grib File: curl \"http://localhost:8080/api/temperature_for_location?latitude=51.5074&longitude=-0.1278&year=2024&month=1&day=1&grib_file=../etc/passwd\"")
    print("5. No Data Found: curl \"http://localhost:8080/api/temperature_for_location?latitude=1.0&longitude=1.0&year=2025&month=1&day=1&grib_file=no_data.grb\"")
    
    # To run:
    # 1. Install dependencies: pip install Flask mysql-connector-python
    # 2. Set environment variables for database connection:
    #    export DB_USER="your_user"
    #    export DB_PASS="your_password"
    # 3. Run the script: python your_script_name.py
    
    app.run(host='0.0.0.0', port=8080, debug=False)