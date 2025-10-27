
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

DB_CONFIG = {
    'host': 'localhost',
    'database': 'weather_db',
    'user': 'root',
    'password': 'password'
}

def get_max_temperature(latitude, longitude, year, month, day, grib_file):
    max_temp = None
    connection = None
    cursor = None
    
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        query = """\n        SELECT MAX(temperature) as max_temp FROM temperature_data \n        WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s \n        AND day = %s AND grib_file = %s\n        """
        
        cursor.execute(query, (latitude, longitude, year, month, day, grib_file))
        result = cursor.fetchone()
        
        if result and result[0] is not None:
            max_temp = result[0]
            
    except Error as e:
        print(f"Database error: {e}")
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
    
    return max_temp

@app.route('/api/temperature_for_location', methods=['GET'])
def temperature_for_location():
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    year = request.args.get('year')
    month = request.args.get('month')
    day = request.args.get('day')
    grib_file = request.args.get('grib_file')
    
    max_temperature = get_max_temperature(latitude, longitude, year, month, day, grib_file)
    
    if max_temperature is not None:
        return jsonify({'max_temperature': max_temperature})
    else:
        return jsonify({'error': 'No data found'}), 404

if __name__ == '__main__':
    print("Test cases:")
    print("1. curl 'http://localhost:5000/api/temperature_for_location?latitude=40.7&longitude=-74.0&year=2023&month=6&day=15&grib_file=data.grib'")
    print("2. curl 'http://localhost:5000/api/temperature_for_location?latitude=51.5&longitude=-0.1&year=2023&month=7&day=20&grib_file=data.grib'")
    print("3. curl 'http://localhost:5000/api/temperature_for_location?latitude=35.6&longitude=139.6&year=2023&month=8&day=10&grib_file=data.grib'")
    print("4. curl 'http://localhost:5000/api/temperature_for_location?latitude=48.8&longitude=2.3&year=2023&month=9&day=25&grib_file=data.grib'")
    print("5. curl 'http://localhost:5000/api/temperature_for_location?latitude=-33.8&longitude=151.2&year=2023&month=10&day=5&grib_file=data.grib'")
    
    app.run(debug=True, port=5000)
