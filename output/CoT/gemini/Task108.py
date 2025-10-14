import threading
import time
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy

# Global configuration
HOST = 'localhost'
PORT = 8000

# 1. Define the object to be exposed on the server
class Calculator:
    """
    This class contains the methods that will be exposed via XML-RPC.
    It does not need to inherit from any special base class.
    """
    def add(self, a, b):
        print(f"Server: Adding {a} and {b}")
        # Basic type validation
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Both arguments must be numeric.")
        return a + b

    def subtract(self, a, b):
        print(f"Server: Subtracting {b} from {a}")
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Both arguments must be numeric.")
        return a - b

    def multiply(self, a, b):
        print(f"Server: Multiplying {a} and {b}")
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Both arguments must be numeric.")
        return a * b

    def divide(self, a, b):
        print(f"Server: Dividing {a} by {b}")
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Both arguments must be numeric.")
        # Server-side input validation for division by zero
        if b == 0:
            raise ValueError("Division by zero is not allowed.")
        return a / b

# 2. Server setup and execution logic
def run_server(server_instance):
    """Function to run the server's main loop."""
    print(f"Server: Starting XML-RPC server on {HOST}:{PORT}...")
    try:
        server_instance.serve_forever()
    except Exception as e:
        print(f"Server: An exception occurred: {e}")
    finally:
        print("Server: Shutting down.")


# 3. Client logic and test cases
def run_client_tests():
    """Connects to the server and runs a series of test cases."""
    # The ServerProxy object allows calling remote methods as if they were local.
    # Note: In a real-world scenario, you should use HTTPS for secure communication.
    try:
        proxy = ServerProxy(f"http://{HOST}:{PORT}")
        print("\nClient: Connected to server. Running test cases...")

        # Test Case 1: Addition
        result = proxy.add(10, 5)
        print(f"Client Test 1 (10 + 5): {result}")

        # Test Case 2: Subtraction
        result = proxy.subtract(10, 5)
        print(f"Client Test 2 (10 - 5): {result}")

        # Test Case 3: Multiplication
        result = proxy.multiply(10, 5)
        print(f"Client Test 3 (10 * 5): {result}")

        # Test Case 4: Division
        result = proxy.divide(10, 5)
        print(f"Client Test 4 (10 / 5): {result}")

        # Test Case 5: Division by zero (error handling)
        try:
            proxy.divide(10, 0)
        except Exception as e:
            print(f"Client Test 5 (10 / 0): Successfully caught expected exception: {e}")

    except ConnectionRefusedError:
        print("Client Error: Connection refused. Is the server running?")
    except Exception as e:
        print(f"Client Error: An unexpected error occurred: {e}")


# 4. Main execution block
if __name__ == "__main__":
    # Create the server instance
    # allow_none=True is not strictly needed here but can be useful.
    # We disable logging of requests for a cleaner output in this example.
    server = SimpleXMLRPCServer((HOST, PORT), logRequests=False, allow_none=True)
    server.register_instance(Calculator())

    # Run the server in a separate daemon thread
    # A daemon thread will exit automatically when the main program exits.
    server_thread = threading.Thread(target=run_server, args=(server,), daemon=True)
    server_thread.start()

    # Give the server a moment to start up
    time.sleep(1)

    # Run the client tests
    run_client_tests()
    
    # Shutdown the server
    # This must be called from a different thread than serve_forever()
    print("\nClient: Tests finished. Signaling server to shut down.")
    server.shutdown()
    server.server_close()
    
    # Wait for the server thread to finish
    server_thread.join(timeout=2)
    print("Program finished.")