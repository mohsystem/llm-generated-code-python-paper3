
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import mysql.connector
import json
import os
import re
import sys

# Database configuration - load from secure environment variables
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'weatherapp'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': 'weather',
    'ssl_disabled': False,  # Enable SSL for production
    'connect_timeout': 10
}
class TemperatureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests to /api/temperature_for_location"""
        # Only handle the specific endpoint
        parsed_path = urlparse(self.path)

        if parsed_path.path != '/api/temperature_for_location':
            self.send_error_response(404, "Endpoint not found")
            return

        try:
            # Parse and validate query parameters - treat all input as untrusted
            params = parse_qs(parsed_path.query)

            # Extract and validate parameters
            latitude = self.validate_float(params.get('latitude', [None])[0], -90.0, 90.0, 'latitude')
            longitude = self.validate_float(params.get('longitude', [None])[0], -180.0, 180.0, 'longitude')
            year = self.validate_int(params.get('year', [None])[0], 1900, 2100, 'year')
            month = self.validate_int(params.get('month', [None])[0], 1, 12, 'month')
            day = self.validate_int(params.get('day', [None])[0], 1, 31, 'day')
            grib_file = self.validate_grib_file(params.get('grib_file', [None])[0])

            # Query database with parameterized query to prevent SQL injection
            max_temp = self.query_max_temperature(latitude, longitude, year, month, day, grib_file)

            if max_temp is not None:
                response = {'max_temperature': max_temp}
                self.send_json_response(200, response)
            else:
                self.send_error_response(404, "No data found")

        except ValueError as e:
            # Generic error - don't leak internal details
            self.send_error_response(400, "Invalid request parameters")
        except Exception as e:
            # Log detailed error internally, return generic message
            print(f"Internal error: {str(e)}", file=sys.stderr)
            self.send_error_response(500, "Internal server error")

    def validate_float(self, value, min_val, max_val, field_name):
        """Validate float input with range checking"""
        if value is None or value == '':
            raise ValueError(f"{field_name} is required")

        try:
            parsed = float(value)
            # Range validation
            if parsed < min_val or parsed > max_val:
                raise ValueError(f"{field_name} out of range")
            return parsed
        except (ValueError, TypeError):
            raise ValueError(f"{field_name} is invalid")

    def validate_int(self, value, min_val, max_val, field_name):
        """Validate integer input with range checking"""
        if value is None or value == '':
            raise ValueError(f"{field_name} is required")

        try:
            parsed = int(value)
            # Range validation
            if parsed < min_val or parsed > max_val:
                raise ValueError(f"{field_name} out of range")
            return parsed
        except (ValueError, TypeError):
            raise ValueError(f"{field_name} is invalid")

    def validate_grib_file(self, grib_file):
        """Validate and sanitize grib_file parameter to prevent path traversal"""
        if grib_file is None or grib_file == '':
            raise ValueError("grib_file is required")

        # Length check
        if len(grib_file) > 100:
            raise ValueError("grib_file too long")

        # Sanitize filename - only allow alphanumeric, underscore, dash, and dot
        # Prevent path traversal attacks
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', grib_file):
            raise ValueError("grib_file contains invalid characters")

        # Block path traversal attempts
        if '..' in grib_file or '/' in grib_file or '\\' in grib_file:
            raise ValueError("grib_file invalid")

        return grib_file

    def query_max_temperature(self, latitude, longitude, year, month, day, grib_file):
        """Query database using parameterized query to prevent SQL injection"""
        connection = None
        cursor = None

        try:
            # Use context manager for automatic cleanup
            connection = mysql.connector.connect(**DB_CONFIG)
            cursor = connection.cursor(prepared=True)

            # Parameterized query prevents SQL injection - parameters are type-safe
            query = """
                    SELECT MAX(temperature) as max_temp
                    FROM temperature_data
                    WHERE latitude = %s AND longitude = %s AND year = %s
                              AND month = %s AND day = %s AND grib_file = %s
                        LIMIT 1 \
                    """

            # Execute with parameters - safe from SQL injection
            cursor.execute(query, (latitude, longitude, year, month, day, grib_file))
            result = cursor.fetchone()

            if result and result[0] is not None:
                return float(result[0])
            return None

        finally:
            # Ensure resources are cleaned up
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    def send_json_response(self, status_code, data):
        """Send JSON response with proper headers"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        response = json.dumps(data).encode('utf-8')
        self.wfile.write(response)

    def send_error_response(self, status_code, message):
        """Send error response"""
        self.send_json_response(status_code, {'error': message})

    def log_message(self, format, *args):
        """Override to control logging format"""
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format % args))


def main():
    """Main function with test cases"""
    print("Starting web server on port 8000...")
    print("Test with:")
    print("curl 'http://localhost:8000/api/temperature_for_location?latitude=40.7128&longitude=-74.0060&year=2023&month=6&day=15&grib_file=gfs_20230615.grb'")

    server_address = ('', 8000)
    httpd = HTTPServer(server_address, TemperatureHandler)
    httpd.serve_forever()


if __name__ == '__main__':
    main()

