import sys
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

def run_server(host="localhost", port=8081):
    """
    Starts and runs the XML-RPC server.
    """
    print(f"Starting XML-RPC server on {host}:{port}")
    # Create server
    # Using '0.0.0.0' makes the server visible externally. Use 'localhost' for local only.
    with SimpleXMLRPCServer((host, port),
                            requestHandler=RequestHandler,
                            allow_none=True) as server:
        server.register_introspection_functions()

        # --- Exposed Functions ---
        
        def add(x, y):
            """
            Adds two numbers.
            Secure: Validates that inputs are numbers.
            """
            if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
                raise TypeError("Both inputs must be numbers.")
            return x + y

        def subtract(x, y):
            """
            Subtracts two numbers.
            Secure: Validates that inputs are numbers.
            """
            if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
                raise TypeError("Both inputs must be numbers.")
            return x - y

        def multiply(x, y):
            """
            Multiplies two numbers.
            Secure: Validates that inputs are numbers.
            """
            if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
                raise TypeError("Both inputs must be numbers.")
            return x * y

        def divide(x, y):
            """
            Divides two numbers.
            Secure: Validates inputs and checks for division by zero.
            """
            if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
                raise TypeError("Both inputs must be numbers.")
            if y == 0:
                raise ValueError("Cannot divide by zero.")
            return x / y
        
        # Register the functions
        server.register_function(add, 'add')
        server.register_function(subtract, 'subtract')
        server.register_function(multiply, 'multiply')
        server.register_function(divide, 'divide')

        # Run the server's main loop
        print("Server started. Use Ctrl+C to stop.")
        
        print("\n--- Test Cases (run from a separate client) ---")
        print("You can use another Python script for testing:")
        print("----------------------------------------------")
        print("import xmlrpc.client")
        print("s = xmlrpc.client.ServerProxy('http://localhost:8081/RPC2')")
        print("# Test Case 1: Add")
        print("print(s.add(10, 20))")
        print("# Test Case 2: Subtract")
        print("print(s.subtract(20, 5))")
        print("# Test Case 3: Multiply")
        print("print(s.multiply(7, 6))")
        print("# Test Case 4: Divide by zero (error handling)")
        print("try:\n    print(s.divide(10, 0))\nexcept Exception as e:\n    print(e)")
        print("# Test Case 5: Invalid input type (error handling)")
        print("try:\n    print(s.add('hello', 'world'))\nexcept Exception as e:\n    print(e)")
        print("----------------------------------------------")
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nServer shutting down.")
            server.server_close()


if __name__ == "__main__":
    # For a real application, consider using command-line arguments for host/port.
    # For security, you would typically run this behind a reverse proxy (like Nginx)
    # that provides TLS (HTTPS) termination and potentially authentication.
    run_server(host="localhost", port=8081)