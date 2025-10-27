
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import mysql.connector
import json
import os
import re

class Lse86(BaseHTTPRequestHandler):
    DB_CONFIG = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'user': os.getenv('DB_USER', 'root'),
        'password': os.getenv('DB_PASSWORD', 'password'),
        'database': os.getenv('DB_NAME', 'weather_db')
    }
    
    def do_GET(self):
        if self.path.startswith('/api/temperature_for_location'):
            self.handle_temperature_request()
        else:
            self.send_error(404, "Not Found")
    
    def handle_temperature_request(self):
        try:
            parsed_url = urlparse(self.path)
            params = parse_qs(parsed_url.query)
            
            latitude = self.validate_float(params.get('latitude', [None])[0], -90, 90)
            longitude = self.validate_float(params.get('longitude', [None])[0], -180, 180)
            year = self.validate_int(params.get('year', [None])[0], 1900, 2100)
            month = self.validate_int(params.get('month', [None])[0], 1, 12)
            day = self.validate_int(params.get('day', [None])[0], 1, 31)
            grib_file = self.validate_string(params.get('grib_file', [None])[0], 100)
            
            if None in [latitude, longitude, year, month, day, grib_file]:
                self.send_json_response(400, {"error": "Invalid parameters"})
                return
            
            max_temp = get_max_temperature(latitude, longitude, year, month, day, grib_file)
            
            if max_temp is not None:
                self.send_json_response(200, {"max_temperature": max_temp})
            else:
                self.send_json_response(404, {"error": "No data found"})
                
        except Exception as e:
            self.send_json_response(500, {"error": "Internal Server Error"})
    
    def validate_float(self, value, min_val, max_val):
        if value is None:
            return None
        try:
            f = float(value)
            return f if min_val <= f <= max_val else None
        except ValueError:
            return None
    
    def validate_int(self, value, min_val, max_val):
        if value is None:
            return None
        try:
            i = int(value)
            return i if min_val <= i <= max_val else None
        except ValueError:
            return None
    
    def validate_string(self, value, max_length):
        if value is None or len(value) > max_length:
            return None
        return re.sub(r'[^a-zA-Z0-9._-]', '', value)
    
    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def get_max_temperature(latitude, longitude, year, month, day, grib_file):
    query = """\n        SELECT MAX(temperature) as max_temp \n        FROM temperature_data \n        WHERE latitude = %s AND longitude = %s AND year = %s \n        AND month = %s AND day = %s AND grib_file = %s\n    """
    
    try:
        conn = mysql.connector.connect(**Lse86.DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute(query, (latitude, longitude, year, month, day, grib_file))
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if result and result['max_temp'] is not None:
            return result['max_temp']
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
    
    return None

def run_test_cases():
    print("\\n=== Test Cases ===")
    
    test_cases = [
        (40.7128, -74.0060, 2023, 6, 15, "test.grb", "NYC"),
        (51.5074, -0.1278, 2023, 7, 20, "test.grb", "London"),
        (35.6762, 139.6503, 2023, 8, 10, "test.grb", "Tokyo"),
        (-33.8688, 151.2093, 2023, 12, 25, "test.grb", "Sydney"),
        (48.8566, 2.3522, 2023, 5, 1, "test.grb", "Paris")
    ]
    
    for lat, lon, y, m, d, grib, location in test_cases:
        result = get_max_temperature(lat, lon, y, m, d, grib)
        print(f"Test - {location} coordinates: {result}")

if __name__ == '__main__':
    run_test_cases()
    
    server = HTTPServer(('localhost', 8080), Lse86)
    print("Server started on port 8080")
    server.serve_forever()
