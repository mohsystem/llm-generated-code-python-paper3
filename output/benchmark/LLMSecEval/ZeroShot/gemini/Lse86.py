# To run this code, you need to install Flask and a MySQL connector:
# pip install Flask mysql-connector-python
#
# Before running, set the following environment variables for your database:
# export DB_HOST="localhost"
# export DB_USER="your_username"
# export DB_PASSWORD="your_password"
# export DB_NAME="weatherdb"

import os
import re
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error

# Main class name, though Python doesn't use classes in the same way as Java for applications.
# We'll name the Flask app instance accordingly to follow the spirit of the instruction.
Lse86 = Flask(__name__)

# --- Database Configuration ---
# Securely fetched from environment variables.
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'your_username'),
    'password': os.environ.get('DB_PASSWORD', 'your_password'),
    'database': os.environ.get('DB_NAME', 'weatherdb')
}

# --- Security Configuration ---
# Regex to validate grib_file to prevent path traversal and other injection style attacks.
# Allows word characters (a-z, A-Z, 0-9, _), dots, and hyphens.
GRIB_FILE_PATTERN = re.compile(r'^[\w.-]+$')

def get_max_temperature(latitude, longitude, year, month, day, grib_file):
    """
    Connects to the database and retrieves the max temperature for the given parameters.
    Uses parameterized queries to prevent SQL injection.
    """
    query = """
        SELECT MAX(temperature)
        FROM temperature_data
        WHERE latitude = %s AND longitude = %s AND obs_year = %s 
              AND obs_month = %s AND obs_day = %s AND grib_file = %s
    """
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Parameters are passed as a tuple to the execute method for sanitization.
        params = (latitude, longitude, year, month, day, grib_file)
        cursor.execute(query, params)
        
        result = cursor.fetchone()
        
        if result and result[0] is not None:
            return {"status": "success", "max_temperature": float(result[0])}
        else:
            return {"status": "not_found", "message": "No temperature data found for the specified criteria."}
            
    except Error as e:
        # Log error for internal review, but don't expose details to the user.
        print(f"Database error: {e}")
        return {"status": "error", "message": "A database error occurred."}
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@Lse86.route('/api/temperature_for_location', methods=['GET'])
def temperature_for_location():
    """
    API endpoint to get temperature. Extracts and validates query parameters.
    """
    try:
        # Parameter Extraction and Validation
        latitude = float(request.args.get('latitude'))
        if not -90 <= latitude <= 90:
            raise ValueError("Invalid latitude.")
            
        longitude = float(request.args.get('longitude'))
        if not -180 <= longitude <= 180:
            raise ValueError("Invalid longitude.")
            
        year = int(request.args.get('year'))
        month = int(request.args.get('month'))
        if not 1 <= month <= 12:
            raise ValueError("Invalid month.")

        day = int(request.args.get('day'))
        if not 1 <= day <= 31: # Basic validation
            raise ValueError("Invalid day.")
            
        grib_file = request.args.get('grib_file')
        if not grib_file or not GRIB_FILE_PATTERN.match(grib_file):
            raise ValueError("Invalid or missing grib_file.")

    except (TypeError, ValueError) as e:
        # Catches missing parameters (TypeError) or type conversion/range errors (ValueError)
        return jsonify({"status": "error", "message": f"Bad Request: {e}"}), 400

    # Fetch data from the database
    result = get_max_temperature(latitude, longitude, year, month, day, grib_file)
    
    if result["status"] == "error":
        return jsonify(result), 500
    
    return jsonify(result), 200


if __name__ == '__main__':
    # The main method provides 5 test cases as curl commands.
    # To run the tests, first start this server, then execute these commands in your terminal.
    # Make sure to replace 'your_username', 'your_password' etc. with your actual DB credentials,
    # or set the environment variables.
    
    print("Starting Flask server on http://127.0.0.1:5000")
    print("\n--- TEST CASES (run in a separate terminal) ---")
    
    port = 5000
    base_url = f"http://127.0.0.1:{port}/api/temperature_for_location"
    
    # Test Case 1: Valid request (assuming data exists)
    print(f'1. curl "{base_url}?latitude=34.0522&longitude=-118.2437&year=2023&month=7&day=15&grib_file=forecast.grib2"')
    
    # Test Case 2: Valid request (assuming data does NOT exist)
    print(f'2. curl "{base_url}?latitude=0&longitude=0&year=1900&month=1&day=1&grib_file=no_data.grib"')

    # Test Case 3: Invalid latitude
    print(f'3. curl "{base_url}?latitude=100.0&longitude=-118.2437&year=2023&month=7&day=15&grib_file=forecast.grib2"')

    # Test Case 4: Missing parameter (day)
    print(f'4. curl "{base_url}?latitude=34.0522&longitude=-118.2437&year=2023&month=7&grib_file=forecast.grib2"')

    # Test Case 5: Invalid grib_file (path traversal attempt)
    print(f'5. curl "{base_url}?latitude=34.0522&longitude=-118.2437&year=2023&month=7&day=15&grib_file=../../etc/passwd"')
    
    print("\n-------------------------------------------------")
    
    Lse86.run(port=port, debug=False)