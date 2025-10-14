import xmlrpc.server
import xmlrpc.client
import threading
import time
from typing import Union

# The server code runs in a separate thread.
class ServerThread(threading.Thread):
    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port
        # Rule #6: The default parser in xmlrpc.server is safe against XXE attacks.
        # Rule #8: The server framework handles exceptions and translates them to faults.
        self.server = xmlrpc.server.SimpleXMLRPCServer(
            (host, port), 
            logRequests=False, # Set to True for debugging
            allow_none=True
        )
        self.server.register_instance(Calculator())
        self.server.register_introspection_functions()

    def run(self):
        print(f"Starting XML-RPC server on {self.host}:{self.port}")
        self.server.serve_forever()

    def shutdown(self):
        print("Shutting down the server.")
        self.server.shutdown()
        self.server.server_close()

class Calculator:
    """A class with methods to be exposed by the XML-RPC server."""
    def add(self, a: int, b: int) -> int:
        """Adds two integers."""
        # Rule #3: Validate input types and values.
        if not isinstance(a, int) or not isinstance(b, int):
            raise TypeError("Both arguments must be integers.")
        return a + b

    def subtract(self, a: int, b: int) -> int:
        """Subtracts second integer from the first."""
        if not isinstance(a, int) or not isinstance(b, int):
            raise TypeError("Both arguments must be integers.")
        return a - b

    def divide(self, a: Union[int, float], b: Union[int, float]) -> float:
        """Divides two numbers."""
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Both arguments must be numbers.")
        if b == 0:
            # Rule #8: Raise an exception for invalid operations.
            raise ValueError("Division by zero is not allowed.")
        return float(a) / float(b)

def run_client_tests(host: str, port: int):
    """Connects to the server and runs test cases."""
    # The server might need a moment to start up
    time.sleep(0.1) 
    
    # Rule #1 & #2: For production, use `ServerProxy` with an `https` URL
    # and a proper `ssl.Context` to ensure secure communication.
    # For this example, we use plain HTTP on localhost.
    proxy = xmlrpc.client.ServerProxy(f"http://{host}:{port}")
    
    print("\n--- Running Client Test Cases ---")
    
    # Test Case 1: Add
    try:
        result = proxy.add(10, 20)
        print(f"Test 1: 10 + 20 = {result}")
    except Exception as e:
        print(f"Test 1 failed: {e}")

    # Test Case 2: Subtract
    try:
        result = proxy.subtract(100, 33)
        print(f"Test 2: 100 - 33 = {result}")
    except Exception as e:
        print(f"Test 2 failed: {e}")

    # Test Case 3: Divide
    try:
        result = proxy.divide(10.0, 4.0)
        print(f"Test 3: 10.0 / 4.0 = {result}")
    except Exception as e:
        print(f"Test 3 failed: {e}")

    # Test Case 4: Divide by zero (error case)
    try:
        proxy.divide(5, 0)
    except xmlrpc.client.Fault as err:
        print(f"Test 4: 5 / 0 -> Fault: {err.faultString.strip()}")

    # Test Case 5: Method not found (error case)
    try:
        proxy.multiply(5, 3)
    except xmlrpc.client.Fault as err:
        print(f"Test 5: call multiply -> Fault: {err.faultString.strip()}")

def main():
    """Main function to start the server and run client tests."""
    host = "localhost"
    port = 8080
    
    server_thread = ServerThread(host, port)
    server_thread.daemon = True # Allows main thread to exit even if server thread is running
    server_thread.start()

    try:
        run_client_tests(host, port)
    finally:
        server_thread.shutdown()
        server_thread.join()

if __name__ == "__main__":
    main()