
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

DB_CONFIG = {
    'host': 'localhost',
    'database': 'weatherdb',
    'user': 'your_username',
    'password': 'your_password'
}

def get_max_temperature(latitude, longitude, year, month, day, grib_file):
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        
        if connection.is_connected():
            cursor = connection.cursor(dictionary=True)
            
            query = """\n                SELECT MAX(temperature) as max_temp \n                FROM temperature_data \n                WHERE latitude = %s AND longitude = %s AND year = %s \n                AND month = %s AND day = %s AND grib_file = %s\n            """
            
            cursor.execute(query, (float(latitude), float(longitude), 
                                  int(year), int(month), int(day), grib_file))
            
            result = cursor.fetchone()
            cursor.close()
            connection.close()
            
            if result and result['max_temp'] is not None:
                return result['max_temp']
            return None
            
    except Error as e:
        print(f"Database error: {e}")
        return None

@app.route('/api/temperature_for_location', methods=['GET'])
def temperature_for_location():
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    year = request.args.get('year')
    month = request.args.get('month')
    day = request.args.get('day')
    grib_file = request.args.get('grib_file')
    
    if not all([latitude, longitude, year, month, day, grib_file]):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    try:
        max_temp = get_max_temperature(latitude, longitude, year, month, day, grib_file)
        
        if max_temp is not None:
            return jsonify({'max_temperature': max_temp})
        else:
            return jsonify({'error': 'No data found'}), 404
            
    except ValueError:
        return jsonify({'error': 'Invalid parameter format'}), 400

if __name__ == '__main__':
    # Test cases
    print("Flask web application")
    print("Test cases:")
    print("1. GET /api/temperature_for_location?latitude=40.7128&longitude=-74.0060&year=2023&month=1&day=15&grib_file=test.grib")
    print("2. GET /api/temperature_for_location?latitude=51.5074&longitude=-0.1278&year=2023&month=6&day=20&grib_file=test2.grib")
    print("3. GET /api/temperature_for_location?latitude=35.6762&longitude=139.6503&year=2023&month=12&day=25&grib_file=test3.grib")
    print("4. GET /api/temperature_for_location?latitude=48.8566&longitude=2.3522&year=2023&month=3&day=10&grib_file=test4.grib")
    print("5. GET /api/temperature_for_location?latitude=-33.8688&longitude=151.2093&year=2023&month=9&day=5&grib_file=test5.grib")
    
    app.run(debug=True, port=5000)
