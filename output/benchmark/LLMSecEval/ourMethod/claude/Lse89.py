
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import re
import sys

# Whitelist of valid product codes with their prices
PRODUCT_PRICES = {
    'PROD001': 10.50,
    'PROD002': 25.00,
    'PROD003': 15.75,
    'PROD004': 30.00,
    'PROD005': 8.99
}

# Input validation pattern for product codes (alphanumeric, max 20 chars)
PRODUCT_CODE_PATTERN = re.compile(r'^[A-Za-z0-9]{1,20}$')

def get_price(product_code: str) -> float:
    """\n    Returns the price for a given product code.\n    \n    Args:\n        product_code: The product code to look up\n        \n    Returns:\n        The price, or None if not found or invalid\n    """
    # Input validation: check for None or empty
    if not product_code:
        return None
    
    # Input validation: check type
    if not isinstance(product_code, str):
        return None
    
    # Input validation: check format against whitelist pattern
    if not PRODUCT_CODE_PATTERN.match(product_code):
        return None
    
    # Return price from secure dictionary (returns None if not found)
    return PRODUCT_PRICES.get(product_code)

def calculate_price(product_code: str, quantity: int) -> float:
    """\n    Calculates total price for a product code and quantity.\n    \n    Args:\n        product_code: The product code\n        quantity: The quantity (must be positive, max 10000)\n        \n    Returns:\n        The total price, or None if invalid\n    """
    # Input validation: check type
    if not isinstance(quantity, int):
        return None
    
    # Input validation: quantity must be positive and within reasonable limits
    if quantity <= 0 or quantity > 10000:
        return None
    
    price = get_price(product_code)
    if price is None:
        return None
    
    # Check for overflow (Python handles big numbers, but we set limits)
    if price > sys.float_info.max / quantity:
        return None
    
    return price * quantity

class PriceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests for price calculation"""
        try:
            # Parse URL and query string
            parsed_url = urlparse(self.path)
            
            # Only handle /price endpoint
            if parsed_url.path != '/price':
                self.send_error_response(404, "Not found")
                return
            
            # Parse query parameters
            query_params = parse_qs(parsed_url.query)
            
            # Input validation: limit number of parameters to prevent DOS
            if len(query_params) > 10:
                self.send_error_response(400, "Too many parameters")
                return
            
            # Extract and validate parameters
            product_code = query_params.get('code', [None])[0]
            quantity_str = query_params.get('quantity', [None])[0]
            
            if product_code is None or quantity_str is None:
                self.send_error_response(400, "Missing required parameters")
                return
            
            # Input validation: limit parameter length
            if len(product_code) > 100 or len(quantity_str) > 100:
                self.send_error_response(400, "Parameter too long")
                return
            
            # Parse quantity with error handling
            try:
                quantity = int(quantity_str)
            except ValueError:
                self.send_error_response(400, "Invalid quantity format")
                return
            
            # Calculate price
            total_price = calculate_price(product_code, quantity)
            
            if total_price is None:
                self.send_error_response(400, "Invalid product code or quantity")
                return
            
            # Send success response with constant format string
            response = f"Total price: {total_price:.2f}"
            self.send_success_response(response)
            
        except Exception:
            # Generic error message, no internal details leaked
            self.send_error_response(500, "Server error")
    
    def send_success_response(self, message: str):
        """Send a successful response"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))
    
    def send_error_response(self, code: int, message: str):
        """Send an error response"""
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to use constant format strings in logging"""
        # Generic logging without exposing sensitive data
        pass

if __name__ == '__main__':
    # Test cases
    print("Test Case 1:", calculate_price("PROD001", 2))  # 21.0
    print("Test Case 2:", calculate_price("PROD002", 3))  # 75.0
    print("Test Case 3:", calculate_price("PROD003", 5))  # 78.75
    print("Test Case 4:", calculate_price("INVALID", 1))  # None
    print("Test Case 5:", calculate_price("PROD001", -1))  # None
    
    # Create and start HTTP server on port 5000
    server = HTTPServer(('0.0.0.0', 5000), PriceHandler)
    print("Server started on port 5000")
    print("Example: http://localhost:5000/price?code=PROD001&quantity=2")
    server.serve_forever()
